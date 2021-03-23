"""Test Terraform installation of new_account_iam_role.

Creates a new role with an attached managed policy and a trust policy.
Verifies the role and policies are attached.  Deletes the new role when
the tests are complete.
"""
import json
import os
from pathlib import Path

import pytest
import tftest

import boto3


AWS_DEFAULT_REGION = os.getenv("AWS_REGION", default="us-east-1")
NEW_ROLE_NAME = "TEST_NEW_ACCOUNT_IAM_ROLE"
MANAGED_POLICY = "ReadOnlyAccess"


@pytest.fixture(scope="module")
def config_path():
    """Find the location of 'main.tf' in current dir or a parent dir."""
    current_dir = Path.cwd()
    if Path(current_dir / "main.tf").exists():
        return str(current_dir)

    # Recurse upwards until the Terraform config file is found.
    for parent in current_dir.parents:
        if Path(parent / "main.tf").exists():
            return str(parent)

    pytest.exit(msg="Unable to find Terraform config file 'main.tf", returncode=1)
    return ""  # Will never reach this point, but satisfies pylint.


@pytest.fixture(scope="module")
def account_id():
    """Return the account ID for the user running this test."""
    sts_client = boto3.client("sts")
    return sts_client.get_caller_identity()["Account"]


@pytest.fixture(scope="module")
def valid_trust_policy(account_id):
    """Return a valid JSON policy for use in testing."""
    valid_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Effect": "Allow",
            }
        ],
    }
    return json.dumps(valid_json)


@pytest.fixture(scope="module")
def tf_output(config_path, account_id, valid_trust_policy):
    """Return the output after applying the Terraform configuration.

    Note:  the scope for this pytest fixture is "module", so this will only
    run once for this file.
    """
    # Terraform requires that AWS_DEFAULT_REGION be set.  If this script is
    # invoked from the command line in a properly setup environment, that
    # environment variable is set, but not if invoked from a Makefile.
    os.environ["AWS_DEFAULT_REGION"] = AWS_DEFAULT_REGION

    tf_test = tftest.TerraformTest(config_path, basedir=None, env=None)
    tf_test.setup()
    tf_vars = {
        "assume_role_name": account_id,
        "role_name": NEW_ROLE_NAME,
        "role_permission_policy": MANAGED_POLICY,
        "trust_policy_json": valid_trust_policy,
    }
    try:
        tf_test.apply(tf_vars=tf_vars)
    except tftest.TerraformTestError as exc:
        tf_test.destroy(tf_vars=tf_vars)
        pytest.exit(
            msg=f"Catastropic error running Terraform 'apply':  {exc}", returncode=1
        )
    yield tf_test.output(json_format=True)
    tf_test.destroy(tf_vars=tf_vars)


def test_outputs(tf_output):
    """Verify outputs of Terraform installation."""
    keys = [*tf_output]
    assert keys == [
        "aws_cloudwatch_event_rule",
        "aws_cloudwatch_event_target",
        "aws_lambda_permission_events",
        "lambda",
    ]
    lambda_module = tf_output["lambda"]
    assert lambda_module["function_name"].startswith("new_account_iam_role")


def test_lambda_dry_run(tf_output):
    """Verify a dry run of the lambda is successful."""
    lambda_client = boto3.client("lambda", region_name=AWS_DEFAULT_REGION)
    lambda_module = tf_output["lambda"]
    response = lambda_client.invoke(
        FunctionName=lambda_module["function_name"],
        InvocationType="DryRun",
    )
    assert response["StatusCode"] == 204


def test_lambda_invocation(tf_output):
    """Verify a role was created with the expected policies."""
    # The following event does not have a valid ID, so the lambda invocation
    # will fail.  However, when it fails, an InvalidInputException should be
    # raised, which should prove the lambda and the AWS powertools library.
    # (The AWS powertools library is invoked to log exceptions.)
    event = {
        "detail": {
            "eventName": "CreateAccount",
            "eventSource": "organizations.amazonaws.com",
            "responseElements": {
                "createAccountStatus": {
                    "id": "xxx-11111111111111111111111111111111",
                }
            },
        },
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.organizations",
    }
    lambda_client = boto3.client("lambda", region_name=AWS_DEFAULT_REGION)
    lambda_module = tf_output["lambda"]
    response = lambda_client.invoke(
        FunctionName=lambda_module["function_name"],
        InvocationType="RequestResponse",
        Payload=json.dumps(event),
    )
    assert response["StatusCode"] == 200

    response_payload = json.loads(response["Payload"].read().decode())
    assert response_payload
    assert "errorType" in response_payload
    assert response_payload["errorType"] == "InvalidInputException"

    # The error message should indicate that the event containined an ID
    # that is not match a valid account.
    assert "errorMessage" in response_payload
    error_msg = (
        "An error occurred (InvalidInputException) when calling the "
        "DescribeCreateAccountStatus operation: You provided a value that "
        "does not match the required pattern."
    )
    assert error_msg in response_payload["errorMessage"]
