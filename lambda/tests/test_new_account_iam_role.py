"""Test event handler and main() of new_account_iam_role.

This is testing a rather basic lambda function, so the tests are
basic as well:

    - test arguments to main()
    - test some of the functions invoked by main()
    - test event handler arguments
"""
from datetime import datetime
import json
import os
import uuid

import boto3
import botocore.exceptions
import pytest
from moto import mock_iam
from moto import mock_sts
from moto import mock_organizations
from moto.core import DEFAULT_ACCOUNT_ID as ACCOUNT_ID

import new_account_iam_role as lambda_func

AWS_REGION = os.getenv("AWS_REGION", default="aws-global")
MOCK_ORG_NAME = "test_account"
MOCK_ORG_EMAIL = f"{MOCK_ORG_NAME}@mock.org"


@pytest.fixture
def lambda_context():
    """Create mocked lambda context injected by the powertools logger."""

    class LambdaContext:  # pylint: disable=too-few-public-methods
        """Mock lambda context."""

        def __init__(self):
            """Initialize context variables."""
            self.function_name = "test"
            self.memory_limit_in_mb = 128
            self.invoked_function_arn = (
                f"arn:aws:lambda:{AWS_REGION}:{ACCOUNT_ID}:function:test"
            )
            self.aws_request_id = str(uuid.uuid4())

    return LambdaContext()


@pytest.fixture(scope="function")
def aws_credentials(tmpdir, monkeypatch):
    """Create mocked AWS credentials for moto.

    In addition to using the aws_credentials fixture, the test functions
    must also use a mocked client.  For this test file, that would be the
    test fixture "iam_client", which invokes "mock_iam()" or "sts_client".
    """
    # Create a temporary AWS credentials file for calls to boto.Session().
    aws_creds = [
        "[testing]",
        "aws_access_key_id = testing",
        "aws_secret_access_key = testing",
    ]
    path = tmpdir.join("aws_test_creds")
    path.write("\n".join(aws_creds))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(path))

    # Ensure that any existing environment variables are overridden with
    # 'mock' values.
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_PROFILE", "testing")  # Not standard, but in use locally.


@pytest.fixture(scope="function")
def iam_client(aws_credentials):
    """Yield a mock IAM client that will not affect a real AWS account."""
    with mock_iam():
        yield boto3.client("iam", region_name=AWS_REGION)


@pytest.fixture(scope="function")
def sts_client(aws_credentials):
    """Yield a mock STS client that will not affect a real AWS account."""
    with mock_sts():
        yield boto3.client("sts", region_name=AWS_REGION)


@pytest.fixture(scope="function")
def org_client(aws_credentials):
    """Yield a mock organization that will not affect a real AWS account."""
    with mock_organizations():
        yield boto3.client("organizations", region_name=AWS_REGION)


@pytest.fixture(scope="function")
def mock_event(org_client):
    """Create an event used as an argument to the Lambda handler."""
    org_client.create_organization(FeatureSet="ALL")
    car_id = org_client.create_account(AccountName=MOCK_ORG_NAME, Email=MOCK_ORG_EMAIL)[
        "CreateAccountStatus"
    ]["Id"]
    create_account_status = org_client.describe_create_account_status(
        CreateAccountRequestId=car_id
    )
    return {
        "version": "0",
        "id": str(uuid.uuid4()),
        "detail-type": "AWS Service Event via CloudTrail",
        "source": "aws.organizations",
        "account": ACCOUNT_ID,
        "time": datetime.now().isoformat(),
        "region": AWS_REGION,
        "resources": [],
        "detail": {
            "eventName": "CreateAccountResult",
            "eventSource": "organizations.amazonaws.com",
            "serviceEventDetails": {
                "createAccountStatus": {
                    "accountId": create_account_status["CreateAccountStatus"][
                        "AccountId"
                    ]
                }
            },
        },
    }


@pytest.fixture(scope="session")
def valid_trust_policy():
    """Return a valid JSON policy for use in testing."""
    valid_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
                "Effect": "Allow",
            }
        ],
    }
    return json.dumps(valid_json)


@pytest.fixture(scope="function")
def valid_role(iam_client, valid_trust_policy):
    """Return a valid role.

    This assumes iam_create_role() works properly, but there are
    tests for that.
    """
    session = boto3.Session(profile_name="testing")
    iam_resource = session.resource("iam")

    role = lambda_func.iam_create_role(
        iam_resource, "TEST_IAM_ROLE_VALID", valid_trust_policy
    )
    return role


def test_invalid_trust_policy_json():
    """Test an invalid JSON string for trust_policy_json argument."""
    with pytest.raises(json.decoder.JSONDecodeError) as exc:
        # JSON string is missing a bracket in the 'Statement' field.
        lambda_func.main(
            role_name="TEST_IAM_ROLE_INVALID_JSON",
            role_permission_policy="ReadOnlyAccess",
            trust_policy_json=(
                f'{{"Version": "2012-10-17", "Statement": '
                f'[{{"Action": "sts:AssumeRole", '
                f'"Principal": {{"AWS": "arn:aws:iam::{ACCOUNT_ID}:root"}}, '
                f'"Effect": "Allow"}}'
            ),
        )
    assert "Expecting ',' delimiter: line 1 column 144 (char 143)" in str(exc.value)


def test_main_func_bad_role_arg(aws_credentials, valid_trust_policy):
    """Invoke main() with a bad role name."""
    with pytest.raises(botocore.exceptions.ClientError) as exc:
        lambda_func.main(
            role_name="TEST$MAIN#BADROLE",
            role_permission_policy="ReadOnlyAccess",
            trust_policy_json=valid_trust_policy,
        )
    assert "The specified value for roleName is invalid" in str(exc.value)


def test_main_func_bad_permission_policy_arg(iam_client, valid_trust_policy):
    """Test use of a bad permission policy argument for main()."""
    with pytest.raises(botocore.exceptions.ClientError) as exc:
        lambda_func.main(
            role_name="TEST_IAM_ROLE_INVALID_PERMISSION_POLICY",
            role_permission_policy="UnknownNotGoodPolicy",
            trust_policy_json=valid_trust_policy,
        )
        assert "Unable to attach 'arn:aws:iam::aws:policy/UnknownNotGoodPolicy'" in str(
            exc.value
        )


def test_main_func_valid_arguments(iam_client, valid_trust_policy):
    """Test use of valid arguments for main()."""
    lambda_func.main(
        role_name="TEST_IAM_ROLE_VALID_ARGS",
        role_permission_policy="ReadOnlyAccess",
        trust_policy_json=valid_trust_policy,
    )

    # Check for role.
    roles = [role["RoleName"] for role in iam_client.list_roles()["Roles"]]
    assert "TEST_IAM_ROLE_VALID_ARGS" in roles

    # Check for attached policy.
    policies = iam_client.list_attached_role_policies(
        RoleName="TEST_IAM_ROLE_VALID_ARGS"
    )
    assert "AttachedPolicies" in policies
    assert "ReadOnlyAccess" in [x["PolicyName"] for x in policies["AttachedPolicies"]]

    # Check for assume role trust policy.
    role_info = iam_client.get_role(RoleName="TEST_IAM_ROLE_VALID_ARGS")
    assert "AssumeRolePolicyDocument" in role_info["Role"]

    expected_trust_statement = json.loads(valid_trust_policy)["Statement"][0]
    trust_statement = role_info["Role"]["AssumeRolePolicyDocument"]["Statement"][0]
    assert trust_statement["Action"] == expected_trust_statement["Action"]
    assert trust_statement["Principal"] == expected_trust_statement["Principal"]
    assert trust_statement["Effect"] == expected_trust_statement["Effect"]


def test_iam_create_role_func_bad_args(aws_credentials, valid_trust_policy):
    """Invoke iam_create_role() using JSON with a bad field name.

    This could tested through a call to main() versus calling
    iam_create_role() directly.  But the test would then have
    to look for an exception rather than a return value.
    """
    session = boto3.Session(profile_name="testing")
    iam_resource = session.resource("iam")

    # Unable to get a bogus trust policy to fail using mocked boto3.
    # bad_trust_policy = '{"Version": "2012-10-17", "nada": []}'
    # role = lambda_func.iam_create_role(
    #    iam_resource, "TEST_IAM_ROLE_BAD_POLICY", bad_trust_policy)

    # But a bad role name will fail with a mocked call.
    with pytest.raises(botocore.exceptions.ClientError) as exc:
        lambda_func.iam_create_role(iam_resource, "TEST#TRUST&ROLE", valid_trust_policy)
        assert "The specified value for roleName is invalid" in exc


def test_iam_attach_bad_policy(valid_role):
    """Invoke iam_attach_policy() with bad arguments.

    This could be tested through a call to main() versus calling
    iam_attach_policy() directly.  But the test would then have
    to look for an exception rather than a return value.
    """
    policy_arn = "arn:aws:iam::aws:policy/NotAwsManagedPolicy"
    with pytest.raises(botocore.exceptions.ClientError) as exc:
        lambda_func.iam_attach_policy(valid_role, policy_arn)
        assert "KeyError" in exc


def test_lambda_handler_valid_arguments(
    lambda_context,
    sts_client,
    iam_client,
    mock_event,
    valid_trust_policy,
    monkeypatch,
):  # pylint: disable=too-many-arguments
    """Invoke the lambda handler with only valid arguments."""
    monkeypatch.setenv("ASSUME_ROLE_NAME", "TEST_VALID_ASSUME_ROLE")
    monkeypatch.setenv("ROLE_NAME", "TEST_IAM_ROLE_VALID_EVENT_ARGS")
    monkeypatch.setenv("PERMISSION_POLICY", "ReadOnlyAccess")
    monkeypatch.setenv("TRUST_POLICY_JSON", valid_trust_policy)
    # The lambda function doesn't return anything, so returning nothing versus
    # aborting with an exception is considered success.
    assert not lambda_func.lambda_handler(mock_event, lambda_context)

    # Assume role into account where lambda created this role
    new_account_id = lambda_func.get_account_id(mock_event)
    sts_response = sts_client.assume_role(
        RoleArn=f"arn:aws:iam::{new_account_id}:role/TEST_VALID_ASSUME_ROLE",
        RoleSessionName="test-session-name",
        ExternalId="test-external-id",
    )
    new_iam_client = boto3.client(
        "iam",
        aws_access_key_id=sts_response["Credentials"]["AccessKeyId"],
        aws_secret_access_key=sts_response["Credentials"]["SecretAccessKey"],
        aws_session_token=sts_response["Credentials"]["SessionToken"],
        region_name=AWS_REGION,
    )

    # Check for role.
    roles = [role["RoleName"] for role in new_iam_client.list_roles()["Roles"]]
    assert "TEST_IAM_ROLE_VALID_EVENT_ARGS" in roles

    # Check for attached policy.
    policies = new_iam_client.list_attached_role_policies(
        RoleName="TEST_IAM_ROLE_VALID_EVENT_ARGS"
    )
    assert "AttachedPolicies" in policies
    assert "ReadOnlyAccess" in [x["PolicyName"] for x in policies["AttachedPolicies"]]

    # Check for assume role trust policy.
    role_info = new_iam_client.get_role(RoleName="TEST_IAM_ROLE_VALID_EVENT_ARGS")
    assert "AssumeRolePolicyDocument" in role_info["Role"]

    expected_trust_statement = json.loads(valid_trust_policy)["Statement"][0]
    trust_statement = role_info["Role"]["AssumeRolePolicyDocument"]["Statement"][0]
    assert trust_statement["Action"] == expected_trust_statement["Action"]
    assert trust_statement["Principal"] == expected_trust_statement["Principal"]
    assert trust_statement["Effect"] == expected_trust_statement["Effect"]


def test_lambda_handler_missing_role_name(
    lambda_context,
    sts_client,
    iam_client,
    mock_event,
    valid_trust_policy,
    monkeypatch,
):  # pylint: disable=too-many-arguments
    """Invoke the lambda handler with no trust policy JSON."""
    monkeypatch.setenv("ASSUME_ROLE_NAME", "TEST_VALID_ASSUME_ROLE")
    monkeypatch.delenv("ROLE_NAME", raising=False)
    monkeypatch.setenv("PERMISSION_POLICY", "ReadOnlyAccess")
    monkeypatch.setenv("TRUST_POLICY_JSON", valid_trust_policy)
    with pytest.raises(lambda_func.IamRoleInvalidArgumentsError) as exc:
        lambda_func.lambda_handler(mock_event, lambda_context)
    assert (
        "Environment variable 'ROLE_NAME' must provide the name of the "
        "IAM role to create"
    ) in str(exc.value)


def test_lambda_handler_missing_permission_policy(
    lambda_context,
    sts_client,
    iam_client,
    mock_event,
    valid_trust_policy,
    monkeypatch,
):  # pylint: disable=too-many-arguments
    """Invoke the lambda handler with no trust policy JSON."""
    monkeypatch.setenv("ASSUME_ROLE_NAME", "TEST_VALID_ASSUME_ROLE")
    monkeypatch.setenv("ROLE_NAME", "TEST_IAM_ROLE_VALID_ARGS")
    monkeypatch.delenv("PERMISSION_POLICY", raising=False)
    monkeypatch.setenv("TRUST_POLICY_JSON", valid_trust_policy)
    with pytest.raises(lambda_func.IamRoleInvalidArgumentsError) as exc:
        lambda_func.lambda_handler(mock_event, lambda_context)
    assert (
        "Environment variable 'PERMISSION_POLICY' must provide the "
        "AWS-managed permission policy"
    ) in str(exc.value)


def test_lambda_handler_missing_trust_policy_json(
    lambda_context,
    sts_client,
    iam_client,
    mock_event,
    monkeypatch,
):  # pylint: disable=too-many-arguments
    """Invoke the lambda handler with no trust policy JSON."""
    monkeypatch.setenv("ASSUME_ROLE_NAME", "TEST_VALID_ASSUME_ROLE")
    monkeypatch.setenv("ROLE_NAME", "TEST_IAM_ROLE_VALID_ARGS")
    monkeypatch.setenv("PERMISSION_POLICY", "ReadOnlyAccess")
    monkeypatch.delenv("TRUST_POLICY_JSON", raising=False)
    with pytest.raises(lambda_func.IamRoleInvalidArgumentsError) as exc:
        lambda_func.lambda_handler(mock_event, lambda_context)
    assert (
        "Environment variable 'TRUST_POLICY_JSON' must be a " "JSON-formatted string"
    ) in str(exc.value)


def test_lambda_handler_invalid_permission_policy(
    lambda_context,
    sts_client,
    iam_client,
    mock_event,
    valid_trust_policy,
    monkeypatch,
):  # pylint: disable=too-many-arguments
    """Invoke the lambda handler with an invalid permission policy.

    Note:  A bad role name does not generate an exception when an assumed
    role is provided to obtain credentials.  But a bad permission policy
    will generate an exception.
    """
    monkeypatch.setenv("ASSUME_ROLE_NAME", "TEST_VALID_ASSUME_ROLE")
    monkeypatch.setenv("ROLE_NAME", "TEST_IAM_ROLE_NAME_BAD_PERM_POLICY")
    monkeypatch.setenv("PERMISSION_POLICY", "BadReadOnlyAccess")
    monkeypatch.setenv("TRUST_POLICY_JSON", valid_trust_policy)
    with pytest.raises(botocore.exceptions.ClientError) as exc:
        lambda_func.lambda_handler(mock_event, lambda_context)
        assert KeyError in exc
