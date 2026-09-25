# Edge-owned transport queue. It exists ONLY to carry this Edge's own encrypted, already-sanitized telemetry, so the runtime
# role can hold send/receive/delete on exactly this queue (docs/edge/DURABLE_DELIVERY.md). SSE-SQS encryption needs no extra
# KMS permission for the role; payloads are additionally AES-256-GCM encrypted by the Edge before they reach SQS.

resource "aws_sqs_queue" "dlq" {
  count                     = var.enable_durable_queue ? 1 : 0
  name                      = "${var.name_prefix}-transport-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "transport" {
  count                      = var.enable_durable_queue ? 1 : 0
  name                       = "${var.name_prefix}-transport"
  message_retention_seconds  = var.queue_retention_seconds
  visibility_timeout_seconds = 120
  sqs_managed_sse_enabled    = true

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq[0].arn
    maxReceiveCount     = 20
  })
}

# Only SQS itself may move messages to the DLQ; the Edge roles have no access to it.
resource "aws_sqs_queue_redrive_allow_policy" "dlq" {
  count     = var.enable_durable_queue ? 1 : 0
  queue_url = aws_sqs_queue.dlq[0].id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.transport[0].arn]
  })
}
