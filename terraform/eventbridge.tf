# ── EventBridge rule — dispara el Lambda detector cada día a las 01:00 UTC
resource "aws_cloudwatch_event_rule" "daily_detector" {
  name                = "elb-anomaly-daily-detection"
  description         = "Dispara el Lambda detector de anomalías ELB cada día a las 01:00 UTC"
  schedule_expression = "cron(0 1 * * ? *)"

  tags = { Project = local.project }
}

resource "aws_cloudwatch_event_target" "detector_target" {
  rule      = aws_cloudwatch_event_rule.daily_detector.name
  target_id = "elb-anomaly-detector"
  arn       = aws_lambda_function.detector.arn
}

resource "aws_lambda_permission" "eventbridge_invoke_detector" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_detector.arn
}
