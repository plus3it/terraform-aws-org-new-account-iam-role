
terraform {
  required_version = ">= 0.12"
}

locals {
  name = "new_account_iam_role_${random_string.id.result}"
}

data "aws_partition" "current" {}

data "aws_iam_policy_document" "lambda" {
  statement {
    actions = [
      "organizations:DescribeCreateAccountStatus"
    ]

    resources = [
      "*",
    ]
  }

  statement {
    actions = [
      "sts:AssumeRole"
    ]

    resources = [
      "arn:${data.aws_partition.current.partition}:iam::*:role/${var.assume_role_name}",
    ]
  }
}

module "lambda" {
  source = "git::https://github.com/plus3it/terraform-aws-lambda.git?ref=v1.3.0"

  function_name = local.name
  description   = "Create new IAM Account Role"
  handler       = "new_account_iam_role.lambda_handler"
  policy        = data.aws_iam_policy_document.lambda
  runtime       = "python3.8"
  source_path   = "${path.module}/lambda/src"
  timeout       = 300

  environment = {
    variables = {
      ASSUME_ROLE_NAME  = var.assume_role_name
      ROLE_NAME         = var.role_name
      PERMISSION_POLICY = var.role_permission_policy
      TRUST_POLICY_JSON = var.trust_policy_json
      LOG_LEVEL         = var.log_level
    }
  }
}

resource "random_string" "id" {
  length  = 13
  special = false
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
