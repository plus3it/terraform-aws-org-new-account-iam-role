
terraform {
  required_version = ">= 0.12"
}

provider "aws" {
  region = var.aws_region
}

locals {
  name = "new_account_iam_role_${random_string.id.result}"
}

resource "random_string" "id" {
  length  = 13
  special = false
}

module "lambda" {
  source = "git::https://github.com/plus3it/terraform-aws-lambda.git?ref=v1.2.0"

  function_name = local.name
  description   = "Create new IAM Account Role"
  handler       = "new_account_iam_role.lambda_handler"
  runtime       = "python3.6"
  source_path   = "${path.module}/new_account_iam_role.py"
  timeout       = 300

  environment = {
    variables = {
      ASSUME_ROLE_NAME  = var.assume_role_arn
      UPDATE_ROLE_NAME  = var.role_name
      PERMISSION_ACTION = var.role_permission_policy
      PERMISSION_POLICY = var.role_permission_action
      TRUST_POLICY      = var.role_trust_policy
      TRUST_ACTION      = var.role_trust_action
      LOG_LEVEL         = var.log_level
    }
  }
}

resource "aws_cloudwatch_event_rule" "this" {
  name          = local.name
  description   = "Managed by Terraform"
  event_pattern = <<-PATTERN
    {
      "source": ["aws.organizations"],
      "detail-type": ["AWS API Call via CloudTrail"],
      "detail": {
        "eventSource": ["organizations.amazonaws.com"],
        "eventName": [
            "InviteAccountToOrganization",
            "CreateAccount",
            "CreateGovCloudAccount"
        ]
      }
    }
    PATTERN
}

resource "aws_cloudwatch_event_target" "this" {
  rule = aws_cloudwatch_event_rule.this.name
  arn  = module.lambda.function_arn
}

resource "aws_lambda_permission" "events" {
  action        = "lambda:InvokeFunction"
  function_name = module.lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.this.arn
}
