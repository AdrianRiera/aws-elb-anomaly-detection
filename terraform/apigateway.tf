# ── API Gateway HTTP v2 ───────────────────────────────────────────────
resource "aws_apigatewayv2_api" "slack_callback" {
  name          = "elb-anomaly-slack-callback"
  protocol_type = "HTTP"

  cors_configuration {
    allow_origins = ["https://slack.com"]
    allow_methods = ["POST", "OPTIONS"]
    allow_headers = ["Content-Type", "X-Slack-Signature", "X-Slack-Request-Timestamp"]
  }

  tags = { Project = local.project }
}

resource "aws_apigatewayv2_integration" "responder" {
  api_id                 = aws_apigatewayv2_api.slack_callback.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.responder.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "slack_check" {
  api_id    = aws_apigatewayv2_api.slack_callback.id
  route_key = "POST /slack/check"
  target    = "integrations/${aws_apigatewayv2_integration.responder.id}"
}

resource "aws_apigatewayv2_stage" "prod" {
  api_id      = aws_apigatewayv2_api.slack_callback.id
  name        = "prod"
  auto_deploy = true

  default_route_settings {
    throttling_rate_limit  = 10
    throttling_burst_limit = 20
  }

  tags = { Project = local.project }
}

resource "aws_lambda_permission" "apigw_invoke_responder" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.slack_callback.execution_arn}/*/*"
}
