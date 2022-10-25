## terraform-aws-org-new-account-iam-role Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/) and this project adheres to [Semantic Versioning](http://semver.org/).

### 1.2.0

**Commit Delta**: [Change from 1.1.1 release](https://github.com/plus3it/terraform-aws-org-new-account-trust-policy/compare/1.1.1...1.2.0)

**Released**: 2022.10.25

**Summary**:

*   Simplifies exception handling with a global handler that logs all exceptions

### 1.1.1

**Commit Delta**: [Change from 1.1.0 release](https://github.com/plus3it/terraform-aws-org-new-account-trust-policy/compare/1.1.0...1.1.1)

**Released**: 2022.10.24

**Summary**:

*   Removes unused `org:DescribeCreateAccountStatus` permission from IAM policy

### 1.1.0

**Commit Delta**: [Change from 1.0.3 release](https://github.com/plus3it/terraform-aws-org-new-account-trust-policy/compare/1.0.3...1.1.0)

**Released**: 2022.10.24

**Summary**:

*   Improves event pattern to eliminate loop/wait logic in lambda function.
*   Separates the CreateAccountResult and InviteAccountToOrganization patterns into two event rules.

### 1.0.3

**Commit Delta**: [Change from 1.0.2 release](https://github.com/plus3it/terraform-aws-org-new-account-trust-policy/compare/1.0.2...1.0.3)

**Released**: 2022.10.20

**Summary**:

*   Ignores terragrunt source manifest by default.
*   Supports customizing the source_path patterns, using var.lambda.source_patterns.

### 1.0.2

**Commit Delta**: [Change from 1.0.1 release](https://github.com/plus3it/terraform-aws-org-new-account-trust-policy/compare/1.0.1...1.0.2)

**Released**: 2022.10.19

**Summary**:

*   Disables ephemeral storage config by default, to better support govcloud.

### 1.0.1

**Commit Delta**: [Change from 1.0.0 release](https://github.com/plus3it/terraform-aws-org-new-account-trust-policy/compare/1.0.0...1.0.1)

**Released**: 2022.10.19

**Summary**:

*   Defaults to ignoring the source code hash. Function is still updated whenever source_path contents change.

### 1.0.0

**Commit Delta**: [Change from 0.4.2 release](https://github.com/plus3it/terraform-aws-org-new-account-trust-policy/compare/0.4.2...1.0.0)

**Released**: 2022.10.14

**Summary**:

*   Changed lambda module to one published by terraform-aws-modules, for better long-term support

*   Exposed new `lambda` variable that wraps arguments for the upstream lambda module

*   Added support for creating multiple instances of this module. This achieved by either:
    *   Tailoring the artifact location, by setting `lambda.artifacts_dir` to a different location for each instance
    *   Creating the package separately from the lambda functions, see `tests/test_create_package_separately` for an example

### 0.4.2

**Commit Delta**: [Change from 0.4.1 release](https://github.com/plus3it/terraform-aws-org-new-account-trust-policy/compare/0.4.1...0.4.2)

**Released**: 2021.07.22

**Summary**:

*   Moved common requirements to `requirements_common.txt`.  Dependabot
    does not want to see duplicate requirements.

*   Updated the `Makefile` to take advantage of new targets in tardigrade-ci.

*   Updated the Travis workflow to reflect changes in tardigrade-ci

### 0.4.1

**Commit Delta**: [Change from 0.4.0 release](https://github.com/plus3it/terraform-aws-org-new-account-trust-policy/compare/0.4.0...0.4.1)

**Released**: 2021.05.18

**Summary**:

*   Update aws-assume-role-lib to fix issue where session name exceeded the 64
    character limit.

### 0.4.0

**Commit Delta**: [Change from 0.3.1 release](https://github.com/plus3it/terraform-aws-org-new-account-iam-role/compare/0.3.1...0.4.0)

**Released**: 2021.04.29

**Summary**:

*   Revise integration test so it can successfully complete the lambda
    invocation.

### 0.3.1

**Commit Delta**: [Change from 0.3.0 release](https://github.com/plus3it/terraform-aws-org-new-account-iam-role/compare/0.3.0...0.3.1)

**Released**: 2021.04.28

**Summary**:

*   Use a different docker name for the integration tests.

### 0.3.0

**Commit Delta**: [Change from 0.2.0 release](https://github.com/plus3it/terraform-aws-org-new-account-iam-role/compare/0.2.0...0.3.0)

**Released**: 2021.04.22

**Summary**:

*   Replaced assume_role boilerplate with the aws_assume_role_lib library.

### 0.2.0

**Commit Delta**: [Change from 0.1.0 release](https://github.com/plus3it/terraform-aws-org-new-account-iam-role/compare/0.1.0...0.2.0)

**Released**: 2021.04.05

**Summary**:

*   Updated the Terraform configuration to add the policy document to 
    provide the Lambda with permissions for sts:AssumeRole and 
    organizations:DescribeCreateAccountStatus.
*   Modified the unit tests to replace the monkeypatched function for
    get_account_id with a call to moto organizations service to set up an 
    obtain an organizations account ID.

### 0.1.0

**Commit Delta**: [Change from 0.0.0 release](https://github.com/plus3it/terraform-aws-org-new-account-iam-role/compare/0.0.0...0.1.0)

**Released**: 2021.03.24

**Summary**:

*   Add support for automated testing of Terraform configuration

### 0.0.0

**Commit Delta**: N/A

**Released**: 2021.02.22

**Summary**:

*   Initial release!
