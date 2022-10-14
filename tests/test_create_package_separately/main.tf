module "test_create_package" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-lambda.git?ref=v4.1.1"

  create_function = false
  create_package  = true

  recreate_missing_package = false

  runtime     = "python3.8"
  source_path = "${path.module}/../../lambda/src"
}

module "test_create_function" {
  source = "../.."

  assume_role_name       = "FOO"
  trust_policy_json      = jsonencode({})
  role_name              = "BAR"
  role_permission_policy = "ReadOnlyAccess"
  log_level              = "Info"

  lambda = {
    local_existing_package = "${path.module}/${module.test_create_package.local_filename}"
    create_package         = false
  }
}
