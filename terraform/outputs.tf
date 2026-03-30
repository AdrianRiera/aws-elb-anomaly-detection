output "api_gateway_url" {
  description = "URL del API Gateway para Slack Interactivity"
  value       = "${aws_apigatewayv2_stage.prod.invoke_url}/slack/check"
}

output "s3_bucket_name" {
  description = "Nombre del bucket S3 donde subir los logs"
  value       = aws_s3_bucket.alb_logs.bucket
}

output "lambda_detector_name" {
  description = "Nombre del Lambda detector"
  value       = aws_lambda_function.detector.function_name
}

output "lambda_responder_name" {
  description = "Nombre del Lambda responder"
  value       = aws_lambda_function.responder.function_name
}

output "alerts_table_name" {
  description = "Nombre de la tabla DynamoDB de alertas"
  value       = aws_dynamodb_table.alerts.name
}

output "validations_table_name" {
  description = "Nombre de la tabla DynamoDB de validaciones"
  value       = aws_dynamodb_table.validations.name
}
