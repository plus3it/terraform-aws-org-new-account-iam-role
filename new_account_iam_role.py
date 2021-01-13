#!/usr/bin/env python3

'''
Create cross-account IAM role and update trust.

References:
https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#role
https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.ServiceResource.create_role
https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/iam.html#IAM.Client.update_role_description

'''

from __future__ import (
    absolute_import,
    division,
    generator_stop,
    generators,
    nested_scopes,
    print_function,
    unicode_literals,
    with_statement,
)

import argparse
import collections
import datetime
import json
import logging
import os
import sys
import time

import boto3
import botocore

# Allow user to override the boto cache dir using the env `BOTOCORE_CACHE_DIR`
# References:
#   * <https://github.com/mixja/boto3-session-cache>
BOTOCORE_CACHE_DIR = os.environ.get("BOTOCORE_CACHE_DIR")

DEFAULT_LOG_LEVEL = logging.INFO
LOG_LEVELS = collections.defaultdict(
    lambda: DEFAULT_LOG_LEVEL,
    {
        "critical": logging.CRITICAL,
        "error": logging.ERROR,
        "warning": logging.WARNING,
        "info": logging.INFO,
        "debug": logging.DEBUG,
    },
)

# Lambda initializes a root logger that needs to be removed
# in order to set a different logging config
ROOT = logging.getLogger()
if ROOT.handlers:
    for handler in ROOT.handlers:
        ROOT.removeHandler(handler)

logging.basicConfig(
    format="%(asctime)s.%(msecs)03dZ [%(name)s][%(levelname)-5s]: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=LOG_LEVELS[os.environ.get("LOG_LEVEL", "").lower()],
)
LOG = logging.getLogger(__name__)


class AccountCreationFailedException(Exception):
    """Account creation failed."""


class AssumeRoleProvider(object):
    """Provide refreshable credentials for assumed role."""

    METHOD = "assume-role"

    def __init__(self, fetcher):
        self._fetcher = fetcher

    def load(self):
        """
        Provide refreshable credentials for assumed role.
        """
        return botocore.credentials.DeferredRefreshableCredentials(
            self._fetcher.fetch_credentials, self.METHOD
        )


def filter_none_values(data):
    """
    Return a new dictionary excluding items where value was None.
    """
    return {k: v for k, v in data.items() if v is not None}


def assume_role(
        session,
        role_arn,
        duration=3600,
        session_name=None,
        serial_number=None,
        cache_dir=None,
):
    """Assume a role with refreshable credentials."""
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
            LOG.error("Account creation failed:\n%s", json.dumps(
                account_status))
            raise AccountCreationFailedException
        LOG.info(
            "Account state: %s. Sleeping 5 seconds and will try again...",
            state)
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


def get_caller_identity(sts=None):
    """Return caller identity from STS."""
    if not sts:
        sts = boto3.client("sts")
    return sts.get_caller_identity()


def iam_update_role_description(session, role_name, description=None):
    """Uses IAM client instead of resource to update the description"""
    iam = session.client('iam')
    if not description:
        description = 'This role was updated {when} by {whom}'.format(
            when=datetime.datetime.now(),
            whom=os.path.basename(__file__)
        )
    iam.update_role_description(RoleName=role_name, Description=description)


def is_json(myjson):
    """https://stackoverflow.com/a/20725965/2275266"""
    try:
        json_object = json.loads(myjson)
    except ValueError as err:
        return False
    return True


def create_assume_policy_doc(policy_item):
    """ Creates the json policy_document from list of account ids
    """
    __function = create_assume_policy_doc.__name__
    policy_document = None

    if isinstance(policy_item, list):
        LOG.debug("%s: Array input detected, converting...", __function)
        # Assume Array is list of account IDs
        # To do: add validation
        trust_acct_statements = list()
        for acct_id in policy_item:
            trust_acct_statements.append({
                "Sid": "",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::{}:root".format(acct_id)
                },
                "Action": "sts:AssumeRole"
            })
        dict_doc = dict()
        dict_doc['Version'] = '2012-10-17'
        dict_doc['Statement'] = trust_acct_statements
        policy_document = json.dumps(dict_doc)
    elif is_json(policy_item):
        LOG.debug("%s: JSON input detected...", __function)
        policy_document = policy_item
    else:
        LOG.error("%s: undefined type '%s'", __function, policy_item.__class__.__name__)
    return policy_document


def iam_role_update_trust(session,
                          role_name=None,
                          action='add',
                          account_ids=None):
    """
    Description:
      Create or Update the 'role_name' from a list of IDs.
    Arguments:
      'session':     BOTO3 Session Resource
      'role_name':   (str) name of role to be created or updated
      'action':      (str; choice) pick one of:
          add:       Ensure array account_ids is allowed to assume the role
          remove:    Ensure array account_ids is not allowed to assume the role
          force:     Ensure array account_ids is the only ones assume the role
      'account_ids': (array) 12 digit AWS IDs to action against the role_name
    """
    if (not account_ids) or (not action) or (not role_name):
        LOG.error(
            "account_ids, action [add|remove|force], and role_name  required!")
        sys.exit(1)
    assert action in [
        'add', 'remove', 'force'], 'Action must be "add", "remove", "force"'

    # Establish IAM Resource
    iam = session.resource('iam')

    # Get Current Role Policy Account IDs
    allowed_ids = list()
    try:
        role = iam.Role(name=role_name)
        role_assume_pol_docs = role.assume_role_policy_document['Statement']
        for stmnt in role_assume_pol_docs:
            if stmnt['Effect'] == 'Allow' and stmnt['Principal']['AWS']:
                allowed_ids.append(stmnt['Principal']['AWS'].split(':')[4])
        allowed_ids.sort()
    except iam.meta.client.exceptions.NoSuchEntityException as exc:
        LOG.debug("Role does not exist yet. Ignoring error: %s", exc)
        role = None
    # create new list of desired Account IDs
    if action == 'add':
        new_allowed_ids = account_ids + list(set(allowed_ids) - set(account_ids))
    if action == 'remove':
        new_allowed_ids = list(set(allowed_ids) - set(account_ids))
    if action == 'force':
        new_allowed_ids = account_ids
    new_allowed_ids.sort()

    assume_role_policy_doc = create_assume_policy_doc(new_allowed_ids)

    try:
        if new_allowed_ids == allowed_ids:
            LOG.debug("%s: Nothing to do, trusts match.", role_name)
        elif role and new_allowed_ids:
            LOG.debug("%s: Updating Existing Role", role_name)
            assume_role_policy = role.AssumeRolePolicy()
            assume_role_policy.update(PolicyDocument=assume_role_policy_doc)
            iam_update_role_description(session, role_name)
            role = role.reload()
        elif role and not new_allowed_ids:
            LOG.warning("%s: Can not remove all trust IDs!", role_name)
            new_allowed_ids = allowed_ids
        else:
            LOG.debug("%s: Creating New Role", role_name)
            role = iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=assume_role_policy_doc)
            iam_update_role_description(session, role_name)
            role = role.reload()
    except iam.meta.client.exceptions.Malformedpolicy_documentumentException as exc:
        LOG.error("Invalid PolicyDocument Detected:\n\t%s", exc)
        new_allowed_ids = allowed_ids
    return (role, new_allowed_ids)


def iam_role_update_policy(session, role=None, action='add', policy_arn=None):
    """Updates the Role by adding or removing a Permission Policy"""
    if (not policy_arn) or (not action) or (not role):
        LOG.error("policy_arn, action [add|remove], and role are required!")
        sys.exit(1)
    assert action in ['add', 'remove'], "Action must be 'add' or 'remove'"
    # Establish IAM Resource
    iam = session.resource('iam')

    if isinstance(role, str):
        role = iam.Role(name=role)

    role_name = role.name

    attached_policies = role.attached_policies.all()

    # Get Current Role Policy Account IDs
    attached_policy_arns = [a.arn for a in role.attached_policies.all()]

    # Update the attached Policies
    if (action == 'add') and (policy_arn not in attached_policy_arns):
        LOG.debug("%s: Updating Existing Role", role_name)
        response = role.attach_policy(PolicyArn=policy_arn)
        iam_update_role_description(session, role_name)
    elif (action == 'remove') and (policy_arn in attached_policy_arns):
        LOG.debug("%s: Updating Existing Role", role_name)
        response = role.detach_policy(PolicyArn=policy_arn)
        iam_update_role_description(session, role_name)
    else:
        LOG.debug("%s: Nothing to do, policy exists.", role_name)

    role.reload()
    return (role, [a.arn for a in role.attached_policies.all()])


def get_partition():
    """Return AWS partition."""
    return get_caller_identity()["Arn"].split(":")[1]


def main(
        aws_profile,
        role_name,
        role_permission_policy,
        role_permission_action,
        role_trust_action,
        role_trust_policy,
        assume_role_arn=None,
        botocore_cache_dir=BOTOCORE_CACHE_DIR,
        log_level=None,
):
    """Create or update a role"""
    LOG.setLevel(level=getattr(logging, log_level.upper()))
    if assume_role_arn:
        # Create a session with an assumed role in the new account
        LOG.info("Establishing Session by Assuming role: %s", assume_role_arn)
        boto = assume_role(
            botocore.session.Session(),
            assume_role_arn,
            cache_dir=botocore_cache_dir,
        )
    elif aws_profile:
        LOG.info("Establishing Session using profile: %s", aws_profile)
        boto = boto3.Session(profile_name=aws_profile)
    else:
        LOG.error("One of '--assume-role-arn' or '--aws-profile' is required")
        sys.exit(1)

    # Update trusts associated with the role
    # Role will be created if it does not exist
    if isinstance(role_trust_policy, str):
        assume_role_ids = role_trust_policy.split(':')
    LOG.info("Targeted Role: %s", role_name)
    LOG.debug("%s: Modifying trust [%s] of AWS Account IDs: %s",
              role_name, role_trust_action, assume_role_ids)
    role, all_trusts = iam_role_update_trust(
        boto, role_name, role_trust_action, assume_role_ids)

    # Update permissions policies associated with the role
    policy_arn = 'arn:aws:iam::{policyOwnerID}:policy/{policyName}'.format(
        policyOwnerID='aws', policyName=role_permission_policy)
    role, all_policies = iam_role_update_policy(
        boto, role_name, role_permission_action, policy_arn)
    LOG.debug("Role Arn: %s\n\ttrusts: %s\n\tPolicies: %s", role.arn,
              all_trusts, all_policies)
    return role.arn


def lambda_handler(event, context):
    """
    Entry point if script called by AWS LAMBDA
    """
    try:
        LOG.info("Received event:\n%s", json.dumps(event))

        # Get vars required to update the role
        account_id = get_account_id(event)
        partition = get_partition()
        assume_role_name = os.environ.get('ASSUME_ROLE_NAME')
        update_role_name = os.environ.get('UPDATE_ROLE_NAME')
        role_arn = f"arn:{partition}:iam::{account_id}:role/{assume_role_name}"
        # name of AWS Permission Policy such as 'ReadOnlyAccess' to de/attach
        permission_action = os.environ.get('PERMISSION_POLICY')
        permission_policy = os.environ.get('PERMISSION_ACTION', 'add')
        # JSON string representing the Assume Role trust policy doc to apply to
        # the role being updated OR a colon ':' delimited list of Account IDs
        trust_policy = os.environ.get('TRUST_POLICY')
        trust_policy = os.environ.get('TRUST_ACTION', 'add')

        # In lambda, override the default boto cache dir because only `/tmp/`
        # is writable
        botocore_cache_dir = BOTOCORE_CACHE_DIR or "/tmp/.aws/boto/cache"

        # Assume the role and update the role trust policy
        main(
            assume_role_arn=role_arn,
            aws_profile=None,
            botocore_cache_dir=botocore_cache_dir,
            role_name=update_role_name,
            role_permission_action='add',
            role_permission_policy=permission_policy,
            role_trust_action='add',
            role_trust_policy=trust_policy,
        )
    except Exception as exc:
        LOG.critical("Caught error: %s", exc, exc_info=exc)
        raise


if __name__ == "__main__":
    PARSER = argparse.ArgumentParser(
        description="Create role and establish trust based on existing policy."
    )
    PARSER.add_argument(
        "--aws-profile",
        help="Credentials profile for IAM user used to establish a session",
    )
    PARSER.add_argument(
        "--assume-role-arn",
        help="ARN of IAM role to assume the target account (case sensitive)",
    )
    PARSER.add_argument(
        "--role-name",
        required=True,
        type=str,
        help="Name of the IAM role to create",
    )
    PARSER.add_argument(
        "--role-permission-action",
        type=str,
        choices=['add', 'remove'],
        default='add',
        help="Takes action on trust-policy-name: + or - from defined role",
    )
    PARSER.add_argument(
        "--role-permission-policy",
        required=True,
        type=str,
        help="delimited [:] list of AWS managed permission policies to action",
    )
    PARSER.add_argument(
        "--role-trust-action",
        type=str,
        choices=['add', 'remove', 'force'],
        default='add',
        help="Takes action on trust-acct-ids: +, -, or == the defined IDs",
    )
    PARSER.add_argument(
        "--role-trust-policy",
        required=True,
        type=str,
        help="JSON or delimited [:] list of Account IDs to modify role trust",
    )
    PARSER.add_argument(
        "--log-level",
        type=str.upper,
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
        default='info',
        help="Set the logging level",
    )
    ARGS = PARSER.parse_args()
    sys.exit(main(**vars(ARGS)))
