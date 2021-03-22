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


class AccountCreationFailedError(Exception):
    """Account creation failed."""


def get_new_account_id(event):
    """Return account id for new account events."""
    create_account_status_id = (
        event["detail"]
        .get("responseElements", {})
        .get("createAccountStatus", {})["id"]  # fmt: no
    )
    LOG.info({"create_account_status_id": create_account_status_id})

    org = boto3.client("organizations")
    while True:
        account_status = org.describe_create_account_status(
            CreateAccountRequestId=create_account_status_id
        )
        state = account_status["CreateAccountStatus"]["State"].upper()
        if state == "SUCCEEDED":
            return account_status["CreateAccountStatus"]["AccountId"]
        if state == "FAILED":
            LOG.error({"create_account_status_failure": account_status})
            raise AccountCreationFailedError
        LOG.info({"create_account_status_state": state})
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
    try:
        account_id = get_account_id_strategy[event_name](event)
    except (botocore.exceptions.ClientError, AccountCreationFailedError) as err:
        raise AccountCreationFailedError(err) from err
    return account_id


def get_partition():
    """Return AWS partition."""
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Arn"].split(":")[1]


### Classes and functions specific to creating the cross-account role.


class IamRoleInvalidArgumentsError(Exception):
    """Invalid arguments were used to create a role or trust policy."""


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
    below, with modifications made for the cache dir:
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


def get_session(assume_role_arn, botocore_cache_dir):
    """Return boto3 session established using a role arn or AWS profile."""
    if assume_role_arn:
        LOG.info({"assumed_role": assume_role_arn})
        boto = assume_role(
            botocore.session.Session(),
            assume_role_arn,
            cache_dir=botocore_cache_dir,
        )
        boto = boto3.session.Session(botocore_session=boto)
    else:
        boto = boto3.session.Session()
    return boto


def iam_create_role(iam_resource, role_name, trust_policy_json):
    """Return role created with role name and assumed trust policy."""
    LOG.info({"role_name": role_name, "trust_policy": trust_policy_json})
    try:
        role = iam_resource.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=trust_policy_json,
            Description=(
                f"This role was updated {datetime.datetime.now()} by "
                f"{os.path.basename(__file__)}"
            ),
        )
    except (
        botocore.exceptions.ClientError,
        botocore.exceptions.ParamValidationError,
        botocore.parsers.ResponseParserError,
    ) as exc:
        role = None
        LOG.error(
            {
                "role_name": role_name,
                "failure_msg": "Unable to create role",
                "failure": exc,
            }
        )
    return role


def iam_attach_policy(role, role_name, policy_arn):
    """Return True if permission policy can be attached, else False."""
    LOG.info({"role_name": role_name, "aws_managed_policy": policy_arn})
    is_success = True
    try:
        role.attach_policy(PolicyArn=policy_arn)
    except (
        botocore.exceptions.ClientError,
        botocore.exceptions.ParamValidationError,
        KeyError,
    ) as exc:
        # Note:  KeyError is seen when the policy ARN has a invalid policy
        # name, e.g. isn't a known policy name.
        LOG.error(
            {
                "role_name": role_name,
                "failure_msg": "Unable to attach policy",
                "failure": exc,
            }
        )
        is_success = False
    return is_success


def main(
    role_name,
    role_permission_policy,
    trust_policy_json,
    assume_role_arn=None,
    partition="aws",
    botocore_cache_dir=BOTOCORE_CACHE_DIR,
):  # pylint: disable=too-many-arguments
    """Create or update a IAM role with a trusted relationship."""
    # Validate trust policy contains properly formatted JSON.  This is
    # not a validation against a schema, so the JSON could still be bad.
    try:
        json.loads(trust_policy_json)
    except json.decoder.JSONDecodeError as exc:
        # pylint: disable=raise-missing-from
        raise IamRoleInvalidArgumentsError(
            f"'trust-policy-json' contains badly formed JSON: {exc}"
        )

    # Create a session using the role arn or AWS profile.
    session = get_session(assume_role_arn, botocore_cache_dir)
    iam_resource = session.resource("iam")

    # Create a role using the role name and assign it an assumed trust policy
    # with the user-supplied JSON.
    role = iam_create_role(iam_resource, role_name, trust_policy_json)
    if not role:
        raise IamRoleInvalidArgumentsError(f"Unable to create '{role_name}' role.")

    # Attach the permission policy(s) associated with the role.
    policy_arn = f"arn:{partition}:iam::aws:policy/{role_permission_policy}"
    if not iam_attach_policy(role, role_name, policy_arn):
        raise IamRoleInvalidArgumentsError(
            f"Unable to attach '{policy_arn}' to {role_name}."
        )
    return 0


@LOG.inject_lambda_context(log_event=True)
def lambda_handler(event, context):  # pylint: disable=unused-argument
    """Entry point if script called by AWS Lamdba."""
    # For the CLI entrypoint (main), argparse will ensure that required
    # arguments are provided.  The Lambda entrypoint uses environment
    # variables to supply "arguments" and checks for required arguments
    # are performed here.

    # Optional:  Used to create assume-role-arn.
    assume_role_name = os.environ.get("ASSUME_ROLE_NAME")

    # Required:  Used for role-name, e.g., E_READONLY or E_PROVADMIN or
    # E_PROVREADONLY.
    role_name = os.environ.get("ROLE_NAME")

    # Required:  role-permission-policy.  AWS-managed permission policy to
    # attach to the role.
    permission_policy = os.environ.get("PERMISSION_POLICY")

    # Required:  trust-policy-json.  JSON-formatted string with trust policy.
    trust_policy_json = os.environ.get("TRUST_POLICY_JSON")

    LOG.info(
        {
            "ASSUME_ROLE_NAME": assume_role_name,
            "ROLE_NAME": role_name,
            "PERMISSION_POLICY": permission_policy,
            "TRUST_POLICY_JSON": trust_policy_json,
        }
    )

    # Check for missing requirement environment variables.
    if not role_name:
        msg = (
            "Environment variable 'ROLE_NAME' must provide "
            "the name of the IAM role to create."
        )
        LOG.error(msg)
        raise IamRoleInvalidArgumentsError(msg)

    if not permission_policy:
        msg = (
            "Environment variable 'PERMISSION_POLICY' must provide "
            "the AWS-managed permission policy to attach to role."
        )
        LOG.error(msg)
        raise IamRoleInvalidArgumentsError(msg)

    if not trust_policy_json:
        msg = (
            "Environment variable 'TRUST_POLICY_JSON' must be a JSON-"
            "formatted string containing the role trust policy."
        )
        LOG.error(msg)
        raise IamRoleInvalidArgumentsError(msg)

    # If there is no default boto cache dir use "/tmp/" as it is writable.
    botocore_cache_dir = BOTOCORE_CACHE_DIR or "/tmp/.aws/boto/cache"

    try:
        account_id = get_account_id(event)
        partition = get_partition()
    except AccountCreationFailedError as account_err:
        LOG.error({"failure": account_err})
        raise
    except Exception:
        LOG.exception("Unexpected, unknown exception in account logic")
        raise

    role_arn = f"arn:{partition}:iam::{account_id}:role/{assume_role_name}"
    try:
        main(
            role_name=role_name,
            role_permission_policy=permission_policy,
            trust_policy_json=trust_policy_json,
            assume_role_arn=role_arn,
            partition=partition,
            botocore_cache_dir=botocore_cache_dir,
        )
    except IamRoleInvalidArgumentsError as err:
        LOG.error({"failure": err})
        raise
    except Exception:
        LOG.exception("Unexpected, unknown exception creating role or policy")
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
            help="AWS-managed permission policy to attach to role",
        )
        required_args.add_argument(
            "--trust-policy-json",
            required=True,
            type=str,
            help="JSON-formatted string containing the new role trust policy",
        )
        parser.add_argument(
            "--assume-role-arn",
            help="ARN of IAM role to assume the target account (case sensitive)",
        )
        return parser.parse_args()

    sys.exit(main(**vars(create_args())))
