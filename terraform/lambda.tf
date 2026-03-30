# ── Lambda detector ───────────────────────────────────────────────────
data "archive_file" "detector" {
  type        = "zip"
  source_file = "${path.module}/../lambda/detector.py"
  output_path = "${path.module}/../lambda/detector.zip"
}

resource "aws_lambda_function" "detector" {
  function_name    = "elb-anomaly-detector"
  role             = aws_iam_role.lambda_detector.arn
  runtime          = "python3.12"
  handler          = "detector.lambda_handler"
  filename         = data.archive_file.detector.output_path
  source_code_hash = data.archive_file.detector.output_base64sha256
  timeout          = 300
  memory_size      = 256

  environment {
    variables = {
      S3_BUCKET         = var.s3_bucket_name
      S3_PREFIX         = "AWSLogs/${var.aws_account_id}/elasticloadbalancing/${var.aws_region}"
      ALERTS_TABLE      = aws_dynamodb_table.alerts.name
      VALIDATIONS_TABLE = aws_dynamodb_table.validations.name
      SLACK_BOT_TOKEN   = var.slack_bot_token
      SLACK_CHANNEL_ID  = var.slack_channel_id
      APP_NAME          = "demo"
    }
  }

  tags = { Project = local.project }
}

# ── Lambda responder ──────────────────────────────────────────────────
data "archive_file" "responder" {
  type        = "zip"
  source_file = "${path.module}/../lambda/responder.py"
  output_path = "${path.module}/../lambda/responder.zip"
}

resource "aws_lambda_function" "responder" {
  function_name    = "elb-anomaly-responder"
  role             = aws_iam_role.lambda_responder.arn
  runtime          = "python3.12"
  handler          = "responder.lambda_handler"
  filename         = data.archive_file.responder.output_path
  source_code_hash = data.archive_file.responder.output_base64sha256
  timeout          = 10
  memory_size      = 128

  environment {
    variables = {
      ALERTS_TABLE         = aws_dynamodb_table.alerts.name
      VALIDATIONS_TABLE    = aws_dynamodb_table.validations.name
      SLACK_BOT_TOKEN      = var.slack_bot_token
      SLACK_SIGNING_SECRET = var.slack_signing_secret
      APP_NAME             = "demo"
    }
  }

  tags = { Project = local.project }
}

# ── CloudWatch Log Groups ─────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "detector" {
  name              = "/aws/lambda/elb-anomaly-detector"
  retention_in_days = 7
}

resource "aws_cloudwatch_log_group" "responder" {
  name              = "/aws/lambda/elb-anomaly-responder"
  retention_in_days = 7
}
