"""Test Terraform installation of new_account_iam_role.

Verifies the Terraform configuration by:
    - verifying the init/plan and apply are successful,
    - verifying the Terraform output,
    - verifying a "dry run" of the lambda is successful,
    - executing the lambda to verify the libraries are installed.
"""
from datetime import datetime
import json
import os
from pathlib import Path
import uuid

import pytest
import tftest

import localstack_client.session


LOCALSTACK_HOST = os.getenv("LOCALSTACK_HOST", default="localhost")

AWS_DEFAULT_REGION = os.getenv("AWS_REGION", default="us-east-1")

# Good values to use as arguments to the Lambda.
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
    return localstack_client.session.Session(localstack_host=LOCALSTACK_HOST)


@pytest.fixture(scope="module")
def mock_event():
    """Create an event used as an argument to the Lambda handler."""
    return {
        "version": "0",
        "id": str(uuid.uuid4()),
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.organizations",
        "account": "222222222222",
        "time": datetime.now().isoformat(),
        "region": AWS_DEFAULT_REGION,
        "resources": [],
        "detail": {
            "eventName": "CreateAccount",
            "eventSource": "organizations.amazonaws.com",
            "responseElements": {
                "createAccountStatus": {
                    "id": "car-123456789",
                }
            },
        },
    }


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
        "localstack_host": LOCALSTACK_HOST,
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

    prefix = "new_account_iam_role"

    lambda_module = tf_output["lambda"]
    assert lambda_module["function_name"].startswith(prefix)

    event_rule_output = tf_output["aws_cloudwatch_event_rule"]
    assert event_rule_output["name"].startswith(prefix)

    event_target_output = tf_output["aws_cloudwatch_event_target"]
    assert event_target_output["rule"].startswith(prefix)

    permission_events_output = tf_output["aws_lambda_permission_events"]
    assert permission_events_output["function_name"].startswith(prefix)


def test_lambda_dry_run(tf_output, localstack_session):
    """Verify a dry run of the lambda is successful."""
    lambda_client = localstack_session.client("lambda", region_name=AWS_DEFAULT_REGION)
    lambda_module = tf_output["lambda"]
    response = lambda_client.invoke(
        FunctionName=lambda_module["function_name"],
        InvocationType="DryRun",
    )
    assert response["StatusCode"] == 204


def test_lambda_invocation(tf_output, localstack_session, mock_event):
    """Verify lambda can be successfully invoked; it will not be executed.

    Not all of the lambda's AWS SDK calls can be mocked for an integration
    test using LocalStack, so the lambda will not be fully executed for this
    test.  The lambda handler will exit just after testing and logging the
    environment variables.
    """
    lambda_client = localstack_session.client("lambda", region_name=AWS_DEFAULT_REGION)
    lambda_module = tf_output["lambda"]
    response = lambda_client.invoke(
        FunctionName=lambda_module["function_name"],
        InvocationType="RequestResponse",
        Payload=json.dumps(mock_event),
    )
    assert response["StatusCode"] == 200

    response_payload = json.loads(response["Payload"].read().decode())
    assert not response_payload
