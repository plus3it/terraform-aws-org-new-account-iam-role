# terraform-aws-org-new-account-iam-role

A Terraform module to bootstrap IAM Roles in new AWS Accounts created through AWS Organizations

## CloudFormation Support

TBD

<!-- BEGIN TFDOCS -->
## Requirements

| Name | Version |
|------|---------|
| terraform | >= 0.12 |

## Providers

| Name | Version |
|------|---------|
| aws | n/a |
| random | n/a |

## Inputs

| Name | Description | Type | Default | Required | case sensitive |
|------|-------------|------|---------|:--------:|:--------------:|
| assume\_role\_arn | ARN of IAM role to assume the target account | `string` | n/a | yes | yes |
| role\_name | Name of the IAM role to create or update in the target account | `string` | n/a | yes | yes |
| role\_permission\_policy | colon [:] delimited list of IAM permission policies names to action | `string` | n/a | yes | yes |
| aws\_region | Region to pass to the AWS resource provider | `string` | n/a | yes | yes |
| role\_permission\_action | ['add' or 'remove'] role_permission\_policy from role\_name | `string` | `"add"` | no | |
| role\_trust\_policy | colon [:] delimited list AWS account IDs (or JSON policyDoc) to assume the role | `string` | n/a | | |
| role\_trust\_action | ['add', 'remove', 'force'] role\_trust\_policy account IDs from role\_name | `string` | `"add"` | no | |
| log\_level | Log level of the lambda output, one of: Debug, Info, Warning, Error, Critical | `string` | `"Info"` | no | |


## Outputs

| Name | Description |
|------|-------------|
| aws\_cloudwatch\_event\_rule | The cloudwatch event rule object |
| aws\_cloudwatch\_event\_target | The cloudWatch event target object |
| aws\_lambda\_permission\_events | The lambda permission object for cloudwatch event triggers |
| lambda | The lambda module object |

<!-- END TFDOCS -->
