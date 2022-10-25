#!/usr/bin/env python3
"""Create cross-account IAM role and update trust."""
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import datetime
import json
import os
import sys

from aws_lambda_powertools import Logger
from aws_assume_role_lib import assume_role, generate_lambda_session_name
import boto3

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


class IamRoleInvalidArgumentsError(Exception):
    """Invalid arguments were used to create a role or trust policy."""


# ------------------------------------------------------------------------
# Classes and functions specific to the Lambda event handler itself.


def get_new_account_id(event):
    """Return account id for new account events."""
    return event["detail"]["serviceEventDetails"]["createAccountStatus"]["accountId"]


def get_invite_account_id(event):
    """Return account id for invite account events."""
    return event["detail"]["requestParameters"]["target"]["id"]


def get_account_id(event):
    """Return account id for supported events."""
    event_name = event["detail"]["eventName"]
    get_account_id_strategy = {
        "CreateAccountResult": get_new_account_id,
        "InviteAccountToOrganization": get_invite_account_id,
    }
    return get_account_id_strategy[event_name](event)


def get_partition():
    """Return AWS partition."""
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Arn"].split(":")[1]


# ------------------------------------------------------------------------


def exception_hook(exc_type, exc_value, exc_traceback):
    """Log all exceptions with hook for sys.excepthook."""
    LOG.exception(
        "%s: %s",
        exc_type.__name__,
        exc_value,
        exc_info=(exc_type, exc_value, exc_traceback),
    )


def get_session(assume_role_arn):
    """Return boto3 session established using a role arn or AWS profile."""
    if not assume_role_arn:
        return boto3.session.Session()

    function_name = os.environ.get(
        "AWS_LAMBDA_FUNCTION_NAME", os.path.basename(__file__)
    )

    LOG.info(
        {
            "comment": f"Assuming role ARN ({assume_role_arn})",
            "assume_role_arn": assume_role_arn,
        }
    )
    return assume_role(
        boto3.Session(),
        assume_role_arn,
        RoleSessionName=generate_lambda_session_name(function_name),
        validate=False,
    )


def iam_create_role(iam_resource, role_name, trust_policy_json):
    """Return role created with role name and trust policy."""
    return iam_resource.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy_json,
        Description=(
            f"This role was updated {datetime.datetime.now()} by "
            f"{os.path.basename(__file__)}"
        ),
    )


def iam_attach_policy(role_resource, policy_arn):
    """Attach managed policy to role."""
    role_resource.attach_policy(PolicyArn=policy_arn)


def main(
    role_name,
    role_permission_policy,
    trust_policy_json,
    assume_role_arn=None,
    partition="aws",
):  # pylint: disable=too-many-arguments
    """Create or update a IAM role with a trusted relationship."""
    # Validate trust policy contains properly formatted JSON.  This is
    # not a validation against a schema, so the JSON could still be bad.
    json.loads(trust_policy_json)

    # Create a session using the role arn or AWS profile.
    session = get_session(assume_role_arn)
    iam_resource = session.resource("iam")

    # Create a role using the role name and assign it an assumed trust policy
    # with the user-supplied JSON.
    LOG.info(
        {
            "comment": f"Creating IAM role ({role_name})",
            "role_name": role_name,
            "trust_policy": trust_policy_json,
        }
    )
    role_resource = iam_create_role(iam_resource, role_name, trust_policy_json)

    # Attach the permission policy(s) associated with the role.
    policy_arn = f"arn:{partition}:iam::aws:policy/{role_permission_policy}"
    LOG.info(
        {
            "comment": "Attaching managed IAM policy ({role_permission_policy})",
            "role_name": role_name,
            "policy_arn": policy_arn,
        }
    )
    iam_attach_policy(role_resource, policy_arn)

    LOG.info(
        "Successfully created IAM role (%s) and attached policy (%s)",
        role_name,
        role_permission_policy,
    )


def check_for_null_envvars(role_name, permission_policy, trust_policy_json):
    """Check for missing requirement environment variables."""
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


@LOG.inject_lambda_context(log_event=True)
def lambda_handler(event, context):  # pylint: disable=unused-argument
    """Entry point if script called by AWS Lamdba."""
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

    check_for_null_envvars(role_name, permission_policy, trust_policy_json)

    # If this handler is invoked for an integration test, exit before invoking
    # any boto3 APIs.
    if os.environ.get("LOCALSTACK_HOSTNAME"):
        return

    account_id = get_account_id(event)
    partition = get_partition()

    role_arn = f"arn:{partition}:iam::{account_id}:role/{assume_role_name}"
    main(
        role_name=role_name,
        role_permission_policy=permission_policy,
        trust_policy_json=trust_policy_json,
        assume_role_arn=role_arn,
        partition=partition,
    )


# Configure exception handler
sys.excepthook = exception_hook

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
