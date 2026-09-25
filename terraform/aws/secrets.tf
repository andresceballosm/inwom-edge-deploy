# The ONLY secret in this deployment: a single-use, 1-hour registration token. After the Edge
# registers, the token is spent; the long-lived identity is a non-exportable KMS key, not a secret.

resource "aws_secretsmanager_secret" "bootstrap" {
  name                    = "${var.name_prefix}/bootstrap-token"
  description             = "Single-use Inwom Edge registration token (spent after first registration)."
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "bootstrap" {
  secret_id     = aws_secretsmanager_secret.bootstrap.id
  secret_string = var.bootstrap_token
}
