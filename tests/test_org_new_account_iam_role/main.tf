module "test_org_new_account_iam_role" {
  source = "../.."

  assume_role_name       = "FOO"
  trust_policy_json      = jsonencode({})
  role_name              = "BAR"
  role_permission_policy = "ReadOnlyAccess"
  log_level              = "Info"
}
