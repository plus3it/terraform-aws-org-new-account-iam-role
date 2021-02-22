"""Test event handler and main() of new_account_iam_role.

This is testing a rather basic lambda function, so the tests are
basic as well:

    - test arguments to main()
    - test some of the functions invoked by main()
    - test event handler arguments
"""
import json
import os
import uuid

import pytest
from moto import mock_iam
from moto import mock_sts
from moto.core import ACCOUNT_ID
import boto3

import new_account_iam_role as lambda_func

AWS_REGION = os.getenv("AWS_REGION", default="aws-global")


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
def aws_credentials(tmpdir):
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
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(path)

    # Ensure that any existing environment variables are overridden with
    # 'mock' values.
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_PROFILE"] = "testing"  # Not standard, but in use locally.


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


@pytest.fixture(scope="function")
def monkeypatch_get_account_id(monkeypatch):
    """Mock get_account_id() to return a fake account ID."""

    def mock_get_account_id(event):  # pylint: disable=unused-argument
        return ACCOUNT_ID

    monkeypatch.setattr(lambda_func, "get_account_id", mock_get_account_id)


def test_invalid_trust_policy_json():
    """Test an invalid JSON string for trust_policy_json argument."""
    with pytest.raises(Exception) as exc:
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
    assert "'trust-policy-json' contains badly formed JSON" in str(exc.value)


def test_main_func_bad_role_arg(aws_credentials, valid_trust_policy):
    """Invoke main() with a bad role name."""
    with pytest.raises(lambda_func.IamRoleInvalidArgumentsError) as exc:
        lambda_func.main(
            role_name="TEST$MAIN#BADROLE",
            role_permission_policy="ReadOnlyAccess",
            trust_policy_json=valid_trust_policy,
        )
    assert "Unable to create 'TEST$MAIN#BADROLE' role" in str(exc.value)


def test_main_func_bad_permission_policy_arg(aws_credentials, valid_trust_policy):
    """Test use of a bad permission policy argument for main()."""
    with pytest.raises(lambda_func.IamRoleInvalidArgumentsError) as exc:
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
    return_code = lambda_func.main(
        role_name="TEST_IAM_ROLE_VALID_ARGS",
        role_permission_policy="ReadOnlyAccess",
        trust_policy_json=valid_trust_policy,
    )
    assert return_code == 0
    roles = [role["RoleName"] for role in iam_client.list_roles()["Roles"]]
    assert "TEST_IAM_ROLE_VALID_ARGS" in roles


def test_iam_create_role_func_bad_args(valid_trust_policy, caplog):
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
    role = lambda_func.iam_create_role(
        iam_resource, "TEST#TRUST&ROLE", valid_trust_policy
    )
    assert not role
    assert "Unable to create role" in caplog.text


def test_iam_attach_policy(valid_role, caplog):
    """Invoke iam_attach_policy() with bad arguments.

    This could be tested through a call to main() versus calling
    iam_attach_policy() directly.  But the test would then have
    to look for an exception rather than a return value.
    """
    policy_arn = "arn:aws:iam::aws:policy/NotAwsManagedPolicy"
    is_success = lambda_func.iam_attach_policy(
        valid_role, "TEST_IAM_ROLE_BAD_POLICY_NAME", policy_arn
    )
    assert not is_success
    assert "Unable to attach policy" in caplog.text


def test_lambda_handler_valid_arguments(
    lambda_context,
    sts_client,
    iam_client,
    monkeypatch_get_account_id,
    valid_trust_policy,
):
    """Invoke the lambda handler with only valid arguments."""
    os.environ["ASSUME_ROLE_NAME"] = "TEST_ASSUME_ROLE"
    os.environ["ROLE_NAME"] = "TEST_IAM_ROLE_VALID_EVENT_ARGS"
    os.environ["PERMISSION_POLICY"] = "ReadOnlyAccess"
    os.environ["TRUST_POLICY_JSON"] = valid_trust_policy
    # The lambda function doesn't return anything, but will generate
    # an exception for failure.  So returning nothing is considered success.
    assert not lambda_func.lambda_handler("mocked_event", lambda_context)
    roles = [role["RoleName"] for role in iam_client.list_roles()["Roles"]]
    assert "TEST_IAM_ROLE_VALID_EVENT_ARGS" in roles


def test_lambda_handler_missing_role_name(
    lambda_context,
    sts_client,
    iam_client,
    monkeypatch_get_account_id,
    valid_trust_policy,
):
    """Invoke the lambda handler with no trust policy JSON."""
    os.environ["ASSUME_ROLE_NAME"] = "TEST_ASSUME_ROLE"
    os.unsetenv("ROLE_NAME")
    os.environ["PERMISSION_POLICY"] = "ReadOnlyAccess"
    os.environ["TRUST_POLICY_JSON"] = valid_trust_policy
    with pytest.raises(lambda_func.IamRoleInvalidArgumentsError) as exc:
        lambda_func.lambda_handler("mocked_event", lambda_context)
    assert (
        "Environment variable 'ROLE_NAME' must provide the name of the "
        "IAM role to create"
    ) in str(exc.value)


def test_lambda_handler_missing_permission_policy(
    lambda_context,
    sts_client,
    iam_client,
    monkeypatch_get_account_id,
    valid_trust_policy,
):
    """Invoke the lambda handler with no trust policy JSON."""
    os.environ["ASSUME_ROLE_NAME"] = "TEST_ASSUME_ROLE"
    os.environ["ROLE_NAME"] = "TEST_IAM_ROLE_VALID_ARGS"
    os.unsetenv("PERMISSION_POLICY")
    os.environ["TRUST_POLICY_JSON"] = valid_trust_policy
    with pytest.raises(lambda_func.IamRoleInvalidArgumentsError) as exc:
        lambda_func.lambda_handler("mocked_event", lambda_context)
    assert (
        "Environment variable 'PERMISSION_POLICY' must provide the "
        "AWS-managed permission policy"
    ) in str(exc.value)


def test_lambda_handler_missing_trust_policy_json(
    lambda_context,
    sts_client,
    iam_client,
    monkeypatch_get_account_id,
):
    """Invoke the lambda handler with no trust policy JSON."""
    os.environ["ASSUME_ROLE_NAME"] = "TEST_ASSUME_ROLE"
    os.environ["ROLE_NAME"] = "TEST_IAM_ROLE_VALID_ARGS"
    os.environ["PERMISSION_POLICY"] = "ReadOnlyAccess"
    os.unsetenv("TRUST_POLICY_JSON")
    with pytest.raises(lambda_func.IamRoleInvalidArgumentsError) as exc:
        lambda_func.lambda_handler("mocked_event", lambda_context)
    assert (
        "Environment variable 'TRUST_POLICY_JSON' must be a " "JSON-formatted string"
    ) in str(exc.value)


def test_lambda_handler_invalid_permission_policy(
    lambda_context,
    sts_client,
    iam_client,
    monkeypatch_get_account_id,
    valid_trust_policy,
):
    """Invoke the lambda handler with an invalid permission policy.

    Note:  A bad role name does not generate an exception when an assumed
    role is provided to obtain credentials.  But a bad permission policy
    will generate an exception.
    """
    os.environ["ASSUME_ROLE_NAME"] = "TEST_ASSUME_ROLE"
    os.environ["ROLE_NAME"] = "TEST_IAM_ROLE_NAME_BAD_PERM_POLICY"
    os.environ["PERMISSION_POLICY"] = "BadReadOnlyAccess"
    os.environ["TRUST_POLICY_JSON"] = valid_trust_policy
    with pytest.raises(lambda_func.IamRoleInvalidArgumentsError) as exc:
        lambda_func.lambda_handler("mocked_event", lambda_context)
    assert "Unable to attach 'arn:aws:iam::aws:policy/BadReadOnlyAccess'" in str(
        exc.value
    )
