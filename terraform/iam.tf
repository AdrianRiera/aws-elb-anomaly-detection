# ── Rol Lambda detector ───────────────────────────────────────────────
resource "aws_iam_role" "lambda_detector" {
  name = "elb-anomaly-lambda-detector-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = { Project = local.project }
}

resource "aws_iam_role_policy" "lambda_detector_policy" {
  name = "elb-anomaly-lambda-detector-policy"
  role = aws_iam_role.lambda_detector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${local.region}:*:*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::${var.s3_bucket_name}",
          "arn:aws:s3:::${var.s3_bucket_name}/*"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:Scan"]
        Resource = [
          aws_dynamodb_table.alerts.arn,
          aws_dynamodb_table.validations.arn,
        ]
      }
    ]
  })
}

# ── Rol Lambda respuesta ──────────────────────────────────────────────
resource "aws_iam_role" "lambda_responder" {
  name = "elb-anomaly-lambda-responder-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })

  tags = { Project = local.project }
}

resource "aws_iam_role_policy" "lambda_responder_policy" {
  name = "elb-anomaly-lambda-responder-policy"
  role = aws_iam_role.lambda_responder.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:${local.region}:*:*"
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:PutItem"]
        Resource = [
          aws_dynamodb_table.alerts.arn,
          aws_dynamodb_table.validations.arn,
        ]
      }
    ]
  })
}

