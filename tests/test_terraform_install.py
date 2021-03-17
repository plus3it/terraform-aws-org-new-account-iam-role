"""Test Terraform installation of new_account_iam_role.

Creates a new role with an attached managed policy and a trust policy.
Verifies the role and policies are attached.  Deletes the new role when
the tests are complete.
"""
import json
import os
from pathlib import Path
import uuid

import pytest
import tftest

import localstack_client.session


AWS_DEFAULT_REGION = os.getenv("AWS_REGION", default="us-east-1")

FAKE_ACCOUNT_ID = "123456789012"
NEW_ROLE_NAME = "TEST_NEW_ACCOUNT_IAM_ROLE"
MANAGED_POLICY = "ReadOnlyAccess"


@pytest.fixture(scope="module")
def config_path():
    """Find the location of 'main.tf' in current dir or a parent dir."""
    current_dir = Path.cwd()
    if list(Path(current_dir).glob("*.tf")):
        return str(current_dir)

    # Recurse upwards until the Terraform config file is found.
    for parent in current_dir.parents:
        if list(Path(parent).glob("*.tf")):
            return str(parent)

    pytest.exit(msg="Unable to find Terraform config file 'main.tf", returncode=1)
    return ""  # Will never reach this point, but satisfies pylint.


@pytest.fixture(scope="module")
def localstack_session():
    """Return a LocalStack client session."""
    return localstack_client.session.Session()


@pytest.fixture(scope="module")
def valid_trust_policy():
    """Return a valid JSON policy for use in testing."""
    valid_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Principal": {"AWS": f"arn:aws:iam::{FAKE_ACCOUNT_ID}:root"},
                "Effect": "Allow",
            }
        ],
    }
    return json.dumps(valid_json)


@pytest.fixture(scope="module")
def tf_output(config_path, valid_trust_policy):
    """Return the output after applying the Terraform configuration.

    Note:  the scope for this pytest fixture is "module", so this will only
    run once for this file.
    """
    # Terraform requires that AWS_DEFAULT_REGION be set.  If this script is
    # invoked from the command line in a properly setup environment, that
    # environment variable is set, but not if invoked from a Makefile.
    os.environ["AWS_DEFAULT_REGION"] = AWS_DEFAULT_REGION

    tf_test = tftest.TerraformTest(config_path, basedir=None, env=None)

    # Use LocalStack to simulate the AWS stack.  "localstack.tf" contains
    # the endpoints and services information needed by LocalStack.
    tf_test.setup(extra_files=[str(Path(Path.cwd() / "tests" / "localstack.tf"))])

    tf_vars = {
        "assume_role_name": FAKE_ACCOUNT_ID,
        "role_name": NEW_ROLE_NAME,
        "role_permission_policy": MANAGED_POLICY,
        "trust_policy_json": valid_trust_policy,
    }

    try:
        tf_test.apply(tf_vars=tf_vars)
        yield tf_test.output(json_format=True)
    except tftest.TerraformTestError as exc:
        pytest.exit(
            msg=f"Catastropic error running Terraform 'apply':  {exc}", returncode=1
        )
    finally:
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

    event_rule_output = tf_output["aws_cloudwatch_event_rule"]
    assert event_rule_output["name"].startswith("new_account_iam_role")

    event_target_output = tf_output["aws_cloudwatch_event_target"]
    assert event_target_output["rule"].startswith("new_account_iam_role")

    permission_events_output = tf_output["aws_lambda_permission_events"]
    assert permission_events_output["function_name"].startswith("new_account_iam_role")


def test_lambda_dry_run(tf_output, localstack_session):
    """Verify a dry run of the lambda is successful."""
    lambda_client = localstack_session.client("lambda", region_name=AWS_DEFAULT_REGION)
    lambda_module = tf_output["lambda"]
    response = lambda_client.invoke(
        FunctionName=lambda_module["function_name"],
        InvocationType="DryRun",
    )
    assert response["StatusCode"] == 204


def test_lambda_invocation(tf_output, localstack_session):
    """Verify a role was created with the expected policies."""
    # The following event does not have a valid ID, so the lambda invocation
    # will fail.  However, when it fails, an InvocationException (or
    # InvalidInputException when using AWS) should be raised.  This proves
    # the lambda and the AWS powertools library are installed.  (The AWS
    # powertools library is invoked to log exceptions.)
    event = {
        "version": "0",
        "id": str(uuid.uuid4()),
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.organizations",
        "account": "222222222222",
        "time": "2021-02-08T16:08:43Z",
        "region": "us-east-1",
        "resources": [],
        "detail": {
            "eventName": "CreateAccount",
            "eventSource": "organizations.amazonaws.com",
            "responseElements": {
                "createAccountStatus": {
                    "id": "xxx-11111111111111111111111111111111",
                }
            },
        },
    }
    lambda_client = localstack_session.client("lambda", region_name=AWS_DEFAULT_REGION)
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
    # The errorType will differ depending on whether the LocalStack is used
    # or not.  For LocalStack, the errorType is InvocationException.  For
    # AWS, the errorType is InvalidInputException.
    assert response_payload["errorType"] == "InvocationException"

    # The error message should indicate that DescribeCreateAccountStatus()
    # failed -- the exact reason why this AWS function fails will differ
    # depends upon whether LocalStack is used or not. For compatibility,
    # the error message text is shortened to the portion that is compatible
    # with the AWS stack or LocalStack.
    assert "errorMessage" in response_payload
    error_msg = (
        "An error occurred (UnrecognizedClientException) when calling the "
        "DescribeCreateAccountStatus operation:"
    )
    assert error_msg in response_payload["errorMessage"]
