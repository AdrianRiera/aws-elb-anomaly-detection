# ── Tabla de alertas — TTL 7 días ──────────────────────────────────────
resource "aws_dynamodb_table" "alerts" {
  name         = "elb-anomaly-alerts"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "alert_date"
  range_key    = "ip"

  attribute {
    name = "alert_date"
    type = "S"
  }

  attribute {
    name = "ip"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Project = local.project
  }
}

# ── Tabla de validaciones — sin TTL ───────────────────────────────────
resource "aws_dynamodb_table" "validations" {
  name         = "elb-anomaly-validations"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "ip"
  range_key    = "app"

  attribute {
    name = "ip"
    type = "S"
  }

  attribute {
    name = "app"
    type = "S"
  }

  tags = {
    Project = local.project
  }
}
