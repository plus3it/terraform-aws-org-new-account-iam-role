provider "aws" {
  region                      = "us-east-1"
  access_key                  = "mock_access_key"
  secret_key                  = "mock_secret_key"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_force_path_style         = true

  endpoints {
    cloudwatch       = "http://localstack:4566"
    cloudwatchevents = "http://localstack:4566"
    cloudwatchlogs   = "http://localstack:4566"
    lambda           = "http://localstack:4566"
    iam              = "http://localstack:4566"
    sts              = "http://localstack:4566"
  }
}
