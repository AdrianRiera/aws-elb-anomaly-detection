variable "slack_bot_token" {
  description = "Token del bot de Slack (xoxb-...)"
  type        = string
  sensitive   = true
}

variable "slack_signing_secret" {
  description = "Secreto de firma de la app de Slack"
  type        = string
  sensitive   = true
}

variable "slack_channel_id" {
  description = "ID del canal de Slack donde se publican las alertas (C...)"
  type        = string
}

variable "s3_bucket_name" {
  description = "Nombre del bucket S3 existente donde se almacenan los logs del ALB"
  type        = string
}

variable "aws_account_id" {
  description = "ID de la cuenta de AWS (número de 12 dígitos)"
  type        = string
}

variable "aws_region" {
  description = "Región de AWS donde se despliegan los recursos"
  type        = string
  default     = "eu-west-1"
}

variable "aws_profile" {
  description = "Perfil de AWS CLI usado para la autenticación"
  type        = string
  default     = "default"
}
