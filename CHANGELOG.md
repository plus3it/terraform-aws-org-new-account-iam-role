## terraform-aws-org-new-account-iam-role Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/) and this project adheres to [Semantic Versioning](http://semver.org/).

### 0.4.0

**Commit Delta**: [Change from 0.3.0 release](https://github.com/plus3it/terraform-aws-org-new-account-iam-role/compare/0.3.0...0.4.0)

**Released**: 2021.04.23

**Summary**:

*   Revise integration test so it can successfully complete the lambda
    invocation.

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
