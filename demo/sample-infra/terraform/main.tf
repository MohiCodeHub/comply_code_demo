terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# --- RDS: Unencrypted, No Backups ---

resource "aws_db_instance" "customer_data" {
  identifier     = "${var.environment}-customer-db"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"

  allocated_storage = 100
  db_name           = "customers"
  username          = "admin"
  password          = var.db_password

  storage_encrypted       = true
  kms_key_id              = "arn:aws:kms:eu-west-1:123456789012:key/your-kms-key-id"
  backup_retention_period = 7
  multi_az                = true
  publicly_accessible     = false
  skip_final_snapshot     = true

  tags = {
    DataClass = "confidential"
    Contains  = "PII"
  }
}

# --- Security Group: Open to the world ---

resource "aws_security_group" "app_sg" {
  name        = "${var.environment}-app-sg"
  description = "Application security group"

  ingress {
    description = "Allow HTTPS traffic from trusted IP ranges"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24", "198.51.100.0/24"]
  }

  ingress {
    description = "Allow SSH from management network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- Remediation for V-f7a3e8b1: Add CloudTrail logging ---

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "my-company-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
  acl    = "private"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs_access_block" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck",
        Effect    = "Allow",
        Principal = { Service = "cloudtrail.amazonaws.com" },
        Action    = "s3:GetBucketAcl",
        Resource  = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite",
        Effect    = "Allow",
        Principal = { Service = "cloudtrail.amazonaws.com" },
        Action    = "s3:PutObject",
        Resource  = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" : "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "compliance_trail" {
  name                          = "compliance-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_logging                = true
  enable_log_file_validation    = true

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

# --- Remediation for V-a1b2c3d4: Add CloudWatch Metric Alarms ---

resource "aws_sns_topic" "critical_alerts_topic" {
  name = "compliance-critical-alerts"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = "arn:aws:sns:*:*:compliance-critical-alerts"
      }
    ]
  })
}

# Example: Alarm for high CPU utilization on a hypothetical EC2 instance
# NOTE: Replace "i-0abcdef1234567890" with an actual instance ID or dynamic lookup
resource "aws_cloudwatch_metric_alarm" "high_cpu_alarm" {
  alarm_name          = "EC2-High-CPU-Utilization"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Triggers when EC2 CPU utilization exceeds 80% for 10 minutes."
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.critical_alerts_topic.arn]
  ok_actions          = [aws_sns_topic.critical_alerts_topic.arn]

  dimensions = {
    InstanceId = "i-0abcdef1234567890"
  }
  treat_missing_data = "notBreaching"
}

# Example: Alarm for too many 5xx errors from an Application Load Balancer
# NOTE: Replace "app/my-load-balancer/50dc6c495c0c9188" with an actual ALB ARN suffix
resource "aws_cloudwatch_metric_alarm" "elb_http_5xx_alarm" {
  alarm_name          = "ALB-HTTP-5xx-Errors"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Triggers when ALB targets return 5 or more 5xx errors in 5 minutes."
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.critical_alerts_topic.arn]
  ok_actions          = [aws_sns_topic.critical_alerts_topic.arn]

  dimensions = {
    LoadBalancer = "app/my-load-balancer/50dc6c495c0c9188"
  }
  treat_missing_data = "notBreaching"
}