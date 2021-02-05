#!/usr/bin/env python3
"""Create cross-account IAM role and update trust."""
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import datetime
import json
import os
import sys
import time

from aws_lambda_powertools import Logger
import boto3
import botocore

# Allow user to override the boto cache dir using the env `BOTOCORE_CACHE_DIR`
# Reference:  <https://github.com/mixja/boto3-session-cache>
BOTOCORE_CACHE_DIR = os.environ.get("BOTOCORE_CACHE_DIR")

LOG_LEVEL = os.environ.get("LOG_LEVEL", "info")

# BOTO_LOG_LEVEL_MAPPING = {"debug": 10, "info": 20, "warning": 30, "error": 40}
# boto3.set_stream_logger("botocore", BOTO_LOG_LEVEL_MAPPING[LOG_LEVEL])

LOG = Logger(
    service="new_account_iam_role",
    level=LOG_LEVEL,
    stream=sys.stderr,
    location="%(name)s.%(funcName)s:%(lineno)d",
    timestamp="%(asctime)s.%(msecs)03dZ",
    datefmt="%Y-%m-%dT%H:%M:%S",
)

### Classes and functions specific to the Lambda event handler itself.


class AccountCreationFailedException(Exception):
    """Account creation failed."""


def get_new_account_id(event):
    """Return account id for new account events."""
    create_account_status_id = (
        event["detail"]
        .get("responseElements", {})
        .get("createAccountStatus", {})["id"]  # fmt: no
    )
    LOG.info("createAccountStatus = %s", create_account_status_id)

    org = boto3.client("organizations")
    while True:
        account_status = org.describe_create_account_status(
            CreateAccountRequestId=create_account_status_id
        )
        state = account_status["CreateAccountStatus"]["State"].upper()
        if state == "SUCCEEDED":
            return account_status["CreateAccountStatus"]["AccountId"]
        if state == "FAILED":
            LOG.error("Account creation failed:\n%s", json.dumps(account_status))
            raise AccountCreationFailedException
        LOG.info("Account state: %s. Sleeping 5 seconds and will try again...", state)
        time.sleep(5)


def get_invite_account_id(event):
    """Return account id for invite account events."""
    return event["detail"]["requestParameters"]["target"]["id"]


def get_account_id(event):
    """Return account id for supported events."""
    event_name = event["detail"]["eventName"]
    get_account_id_strategy = {
        "CreateAccount": get_new_account_id,
        "CreateGovCloudAccount": get_new_account_id,
        "InviteAccountToOrganization": get_invite_account_id,
    }
    return get_account_id_strategy[event_name](event)


def get_partition():
    """Return AWS partition."""
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Arn"].split(":")[1]


### Classes and functions specific to creating the cross-account role.


class AssumeRoleProvider:  # pylint: disable=too-few-public-methods
    """Provide refreshable credentials for assumed role."""

    METHOD = "assume-role"

    def __init__(self, fetcher):
        """Initialize class variables."""
        self._fetcher = fetcher

    def load(self):
        """Provide refreshable credentials for assumed role."""
        return botocore.credentials.DeferredRefreshableCredentials(
            self._fetcher.fetch_credentials, self.METHOD
        )


def filter_none_values(data):
    """Return a new dictionary excluding items where value was None."""
    return {k: v for k, v in data.items() if v is not None}


def assume_role(
    session,
    role_arn,
    duration=3600,
    session_name=None,
    serial_number=None,
    cache_dir=None,
):  # pylint: disable=too-many-arguments
    """Return an assumed role session with refreshable credentials.

    Code for this function and class AccountRoleProvider were taken from
    below, with modifications for the cache dir:
        https://github.com/boto/botocore/issues/761
    """
    cache_dir = cache_dir or botocore.credentials.JSONFileCache.CACHE_DIR

    fetcher = botocore.credentials.AssumeRoleCredentialFetcher(
        session.create_client,
        session.get_credentials(),
        role_arn,
        extra_args=filter_none_values(
            {
                "DurationSeconds": duration,
                "RoleSessionName": session_name,
                "SerialNumber": serial_number,
            }
        ),
        cache=botocore.credentials.JSONFileCache(working_dir=cache_dir),
    )

    role_session = botocore.session.Session()
    role_session.register_component(
        "credential_provider",
        botocore.credentials.CredentialResolver([AssumeRoleProvider(fetcher)]),
    )
    return role_session


def get_session(assume_role_arn, aws_profile, botocore_cache_dir):
    """Return session established through the role arn or our AWS profile."""
    if assume_role_arn:
        LOG.info("Establishing session by assuming role: %s", assume_role_arn)
        boto = assume_role(
            botocore.session.Session(),
            assume_role_arn,
            cache_dir=botocore_cache_dir,
        )
    elif aws_profile:
        LOG.info("Establishing session using profile: %s", aws_profile)
        boto = boto3.Session(profile_name=aws_profile)
    return boto


def iam_update_role_description(iam_client, role_name):
    """Update the role description with timestamp and program filename."""
    description = (
        f"This role was updated {datetime.datetime.now()} by "
        f"{os.path.basename(__file__)}"
    )
    iam_client.update_role_description(RoleName=role_name, Description=description)


def iam_role_create_trust(iam_resource, iam_client, role_name, trust_policy):
    """Return role created with role name and assumed trust policy."""
    LOG.info("%s: Adding trust relationship: %s", role_name, trust_policy)
    try:
        role = iam_resource.create_role(
            RoleName=role_name, AssumeRolePolicyDocument=trust_policy
        )
        iam_update_role_description(iam_client, role_name)
        role.reload()
    except botocore.exceptions.ClientError as err:
        role = None
        LOG.error("%s: Unable to create role:\n\t%s", role_name, err)
    return role


def iam_role_create_policy(iam_client, role, role_name, policy_arn):
    """Attach or detach the permission policy."""
    LOG.info("%s: Attaching policy %s", role_name, policy_arn)
    try:
        role.attach_policy(PolicyArn=policy_arn)
        iam_update_role_description(iam_client, role_name)
        role.reload()
    except botocore.exceptions.ClientError as err:
        LOG.error("%s: Unable to attach policy:\n\t%s", role_name, err)


def main(
    aws_profile,
    role_name,
    role_permission_policy,
    trust_policy,
    assume_role_arn=None,
    botocore_cache_dir=BOTOCORE_CACHE_DIR,
):  # pylint: disable=too-many-arguments
    """Create or update a IAM role with a trusted relationship."""
    # Validate trust policy contains properly formatted JSON.  This is
    # not a validation against a schema, so the JSON could still be bad.
    try:
        json.loads(trust_policy)
    except json.decoder.JSONDecodeError as exc:
        # pylint: disable=raise-missing-from
        raise Exception(
            f"'trust-policy' contains badly formed JSON:"
            f"\n\t{exc}\n\tJSON input:  {trust_policy}"
        )

    # Validate that either role arn or an AWS profile was supplied, as one
    # of them is needed to create a AWS session.
    if not assume_role_arn and not aws_profile:
        raise Exception("One of 'assume-role-arn' or 'aws-profile' is required")

    # Create a session using the role arn or AWS profile.
    session = get_session(assume_role_arn, aws_profile, botocore_cache_dir)
    iam_resource = session.resource("iam")
    iam_client = session.client("iam")

    # Create a role using the role name and assign it an assumed trust policy
    # with the user-supplied JSON.
    role = iam_role_create_trust(iam_resource, iam_client, role_name, trust_policy)
    if not role:
        raise Exception(f"Unable to create '{role_name}' role.")

    # Detach the permission policy(s) associated with the role.
    policy_arn = f"arn:aws:iam::aws:policy/{role_permission_policy}"
    iam_role_create_policy(iam_client, role, role_name, policy_arn)
    return 0


def lambda_handler(event, context):  # pylint: disable=unused-argument
    """Entry point if script called by AWS LAMBDA."""
    LOG.info("Received event:\n%s", json.dumps(event))

    # For the CLI entrypoint (main), argparse will ensure that required
    # arguments are provided and that arguments are restricted as necessary.
    # The Lambda entrypoint uses environment variables to supply "arguments"
    # and those checks must be performed here.

    # Optional:  Used to create assume-role-arn.
    assume_role_name = os.environ.get("ASSUME_ROLE_NAME")

    # Required:  Used for role-name, e.g., E_READONLY or E_PROVADMIN or
    # E_PROVREADONLY.
    role_name = os.environ.get("ROLE_NAME")

    # Required:  role-permission-policy.  Name of AWS Permission Policy
    # such as 'ReadOnlyAccess' to de/attach.
    permission_policy = os.environ.get("PERMISSION_POLICY")

    # Required:  trust-policy.  JSON-formatted string with trust policy.
    trust_policy = os.environ.get("TRUST_POLICY")

    LOG.info(
        "Environment variables:\n\tASSUME_ROLE_NAME=%s\n\tROLE_NAME=%s"
        "\n\tPERMISSION_POLICY=%s\n\tTRUST_POLICY=%s",
        assume_role_name,
        role_name,
        permission_policy,
        json.dumps(json.loads(trust_policy), indent=4),
    )

    if not role_name:
        LOG.critical(
            "Environment variable 'ROLE_NAME' must provide "
            "the name of the IAM role to create."
        )
    if not permission_policy:
        LOG.critical(
            "Environment variable 'PERMISSION_POLICY' must provide "
            "the list of AWS managed permission policies to action."
        )
    if not trust_policy:
        LOG.critical(
            "Environment variable 'TRUST_POLICY' must be a JSON-formatted "
            "containing the role trust policy."
        )

    # Override the default boto cache dir because only `/tmp/` is writable.
    botocore_cache_dir = BOTOCORE_CACHE_DIR or "/tmp/.aws/boto/cache"

    try:
        account_id = get_account_id(event)
        partition = get_partition()
        role_arn = f"arn:{partition}:iam::{account_id}:role/{assume_role_name}"

        main(
            aws_profile=None,
            role_name=role_name,
            role_permission_policy=permission_policy,
            trust_policy=trust_policy,
            assume_role_arn=role_arn,
            botocore_cache_dir=botocore_cache_dir,
        )
    except Exception as exc:
        LOG.exception("Caught error: %s", exc, exc_info=exc)
        raise


if __name__ == "__main__":

    def create_args():
        """Return parsed arguments."""
        parser = ArgumentParser(
            formatter_class=RawDescriptionHelpFormatter,
            description="""
Create role and establish trust based on existing policy.

NOTE:  Use the environment variable 'LOG_LEVEL' to set the desired log level
('error', 'warning', 'info' or 'debug').  The default level is 'info'.""",
        )
        required_args = parser.add_argument_group("required named arguments")
        parser.add_argument(
            "--aws-profile",
            help="Credentials profile for IAM user used to establish a session",
        )
        required_args.add_argument(
            "--role-name",
            required=True,
            type=str,
            help="Name of the IAM role to create",
        )
        required_args.add_argument(
            "--role-permission-policy",
            required=True,
            type=str,
            help="delimited [:] list of AWS managed permission policies to action",
        )
        required_args.add_argument(
            "--trust-policy",
            required=True,
            type=str,
            help="JSON-formatted string containing the new role trust policy.",
        )
        parser.add_argument(
            "--assume-role-arn",
            help="ARN of IAM role to assume the target account (case sensitive)",
        )
        return parser.parse_args()

    sys.exit(main(**vars(create_args())))
