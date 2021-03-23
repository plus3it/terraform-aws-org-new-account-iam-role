provider "aws" {
  region                      = "us-east-1"
  access_key                  = "mock_access_key"
  secret_key                  = "mock_secret_key"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_force_path_style         = true

  endpoints {
    cloudwatch       = "http://localhost:4566"
    cloudwatchevents = "http://localhost:4566"
    cloudwatchlogs   = "http://localhost:4566"
    lambda           = "http://localhost:4566"
    iam              = "http://localhost:4566"
    sts              = "http://localhost:4566"
  }
}
