# Agent Instructions

Before starting any task in this repository:

1. Run `make agents/sync`. It writes the shared Plus3 IT instructions for this repository's tardigrade-ci version to `.agents/plus3it/AGENTS.md`.
2. Read `.agents/plus3it/AGENTS.md` and follow it together with this file. If the sync fails, tell the user, and don't guess the conventions.

These rules always apply, even without the shared instructions:

- Don't push, open pull requests, publish releases, or apply infrastructure changes unless the user asks. List those steps for a person in your final report.
- Don't edit files under `.agents/plus3it/`; they are generated and overwritten by the sync.

@.agents/plus3it/AGENTS.md

## Repository-specific

### Purpose

This Terraform module deploys a Python Lambda function, invoked by EventBridge (CloudWatch Events) rules for new or invited AWS Organizations accounts, that assumes a role in the new account and creates an IAM role there with an AWS-managed permission policy attached. The required inputs are `assume_role_name`, `role_name`, `role_permission_policy`, and `trust_policy_json`; `event_types` selects the triggering events (`CreateAccountResult`, `InviteAccountToOrganization`) and `lambda` passes extra settings to the upstream Lambda module. It outputs `lambda` (the upstream module object), `aws_cloudwatch_event_rule`, `aws_cloudwatch_event_target`, and `aws_lambda_permission_events`.

### Module-specific files

- `lambda/src/` — Source of the Lambda function (`new_account_iam_role.py`), packaged by the module with the upstream Lambda module; `requirements.txt` lists its runtime packages
- `lambda/tests/` — Python unit tests for the Lambda function, which use `moto`
- `requirements/` — Test packages: `requirements_common.txt` (`pytest`, `moto`), `requirements_dev.txt`, and `requirements_test.txt` (`tftest`, `localstack-client`); both of those include the common file
- `tests/test_terraform_install.py` — Python test that applies the module to LocalStack, using `tests/localstack.tf` (provider endpoints) and `tests/docker-compose-localstack.yml` (LocalStack container)
- `Dockerfile` and `Dockerfile_test` — Images based on tardigrade-ci that preinstall the Python packages: `Dockerfile` installs the runtime, dev, and test requirements, and `Dockerfile_test` only the test requirements

### Deviations from the terraform-module profile

- The Makefile sets `TERRAFORM_PYTEST_DIR` to this repository's `tests/` directory, so `terraform/pytest` runs `tests/test_terraform_install.py` and `make mockstack/up` uses `tests/docker-compose-localstack.yml`, instead of the tardigrade-ci defaults. The Makefile also adds `./lambda/src` to `PYTHONPATH`, so the unit tests can import the Lambda module.
- Python unit tests run in a separate `unit-test` job in `.github/workflows/test.yml`, in addition to the shared test workflow that runs the mockstack tests. The job runs `make docker/run target=pytest/lambda/tests`, which runs `pytest lambda/tests` inside the image built from `Dockerfile` (the tardigrade-ci `pytest/%` target).
- The Makefile adds these targets. None of them runs in CI.
  - `pytest/deps` installs `requirements/requirements_dev.txt` and `requirements/requirements_test.txt` with `python -m pip`.
  - `python/deps` installs `lambda/src/requirements.txt` with `python -m pip`.
  - `mockstack/pytest/lambda` runs `terraform/pytest` in a container on the `terraform_pytest_default` network with `LOCALSTACK_HOST=localstack`, using `Dockerfile_test` and the image `new-account-iam-role-integration-test:latest`. It needs the LocalStack container from `make mockstack/up`.
- The shared `mockstack/pytest` target, which CI runs, uses the image `<directory name>-integration-test:latest`, built from `Dockerfile` if it is missing. Locally, run Python unit tests with `make docker/run target=pytest/lambda/tests`, and Terraform tests with `make mockstack/up`, then `make mockstack/pytest/lambda` (or `make mockstack/pytest`), then `make mockstack/clean`.
