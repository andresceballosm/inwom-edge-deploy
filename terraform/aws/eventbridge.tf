# Optional near-real-time input. Deploy in each monitored Region (CloudTrail events are regional).
# The CloudTrail trail must already capture management and the required data events.
resource "aws_sqs_queue" "cloudtrail_dlq" {
  count                     = var.enable_cloudtrail_streaming ? 1 : 0
  name                      = "${var.name_prefix}-cloudtrail-input-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "cloudtrail_input" {
  count                      = var.enable_cloudtrail_streaming ? 1 : 0
  name                       = "${var.name_prefix}-cloudtrail-input"
  message_retention_seconds  = 345600
  visibility_timeout_seconds = 300
  sqs_managed_sse_enabled    = true
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.cloudtrail_dlq[0].arn
    maxReceiveCount     = 10
  })
}

resource "aws_sqs_queue_redrive_allow_policy" "cloudtrail_dlq" {
  count     = var.enable_cloudtrail_streaming ? 1 : 0
  queue_url = aws_sqs_queue.cloudtrail_dlq[0].id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.cloudtrail_input[0].arn]
  })
}

resource "aws_cloudwatch_event_rule" "cloudtrail_input" {
  count = var.enable_cloudtrail_streaming ? 1 : 0
  name  = "${var.name_prefix}-cloudtrail-input"
  # ENABLED alone excludes read-only management events, including reconnaissance.
  state = "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS"
  event_pattern = jsonencode({
    account       = [data.aws_caller_identity.current.account_id]
    "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Signin via CloudTrail", "AWS Console Action via CloudTrail", "AWS Service Event via CloudTrail"]
  })
}

resource "aws_sqs_queue_policy" "cloudtrail_input" {
  count     = var.enable_cloudtrail_streaming ? 1 : 0
  queue_url = aws_sqs_queue.cloudtrail_input[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.cloudtrail_input[0].arn
      Condition = {
        ArnEquals    = { "aws:SourceArn" = aws_cloudwatch_event_rule.cloudtrail_input[0].arn }
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
      }
    }]
  })
}

resource "aws_cloudwatch_event_target" "cloudtrail_input" {
  count      = var.enable_cloudtrail_streaming ? 1 : 0
  rule       = aws_cloudwatch_event_rule.cloudtrail_input[0].name
  target_id  = "edge-cloudtrail-input"
  arn        = aws_sqs_queue.cloudtrail_input[0].arn
  depends_on = [aws_sqs_queue_policy.cloudtrail_input]
}
