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

# --- KMS Key for Customer Data Encryption ---
resource "aws_kms_key" "customer_data_key" {
  description             = "KMS key for customer data encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  tags = {
    Name      = "${var.environment}-customer-data-kms-key"
    DataClass = "confidential"
  }
}

# --- RDS: Compliant Configuration ---

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
  kms_key_id              = aws_kms_key.customer_data_key.arn
  backup_retention_period = 7 # Set to 7 days, adjust as per RPO
  multi_az                = true
  publicly_accessible     = false
  skip_final_snapshot     = true

  tags = {
    DataClass = "confidential"
    Contains  = "PII"
  }
}

# --- Security Group: Restricted Access ---

resource "aws_security_group" "app_sg" {
  name        = "${var.environment}-app-sg"
  description = "Application security group"

  # Removed problematic ingress rule allowing 0.0.0.0/0 to all ports.
  # Add a restricted ingress rule for necessary access.
  ingress {
    from_port   = 443 # Example: HTTPS port
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"] # Example: specific internal network CIDR
    description = "Allow HTTPS access from internal network"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- CloudTrail for Auditing and Logging ---

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket = "my-company-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
  acl    = "private"
  versioning { enabled = true }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = {
    Name = "${var.environment}-cloudtrail-logs"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_bucket_public_access_block" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudwatch_log_group" "cloudtrail_log_group" {
  name              = "/aws/cloudtrail/my-company-cloudtrail"
  retention_in_days = 365

  tags = {
    Name = "${var.environment}-cloudtrail-log-group"
  }
}

resource "aws_iam_role" "cloudtrail_cloudwatch_role" {
  name = "${var.environment}-cloudtrail-cloudwatch-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action    = "sts:AssumeRole",
        Effect    = "Allow",
        Principal = { Service = "cloudtrail.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch_policy" {
  name = "${var.environment}-cloudtrail-cloudwatch-policy"
  role = aws_iam_role.cloudtrail_cloudwatch_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = ["logs:CreateLogStream", "logs:PutLogEvents"],
        Effect   = "Allow",
        Resource = ["${aws_cloudwatch_log_group.cloudtrail_log_group.arn}:*"]
      }
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "${var.environment}-my-company-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_bucket.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = aws_cloudwatch_log_group.cloudtrail_log_group.arn
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cloudwatch_role.arn

  tags = {
    Name = "${var.environment}-cloudtrail"
  }
}

# --- CloudWatch Alarms for Critical Monitoring ---

resource "aws_sns_topic" "critical_alarms_topic" {
  name = "${var.environment}-critical-system-alarms"

  tags = {
    Name = "${var.environment}-critical-alarms-sns-topic"
  }
}

resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.critical_alarms_topic.arn
  protocol  = "email"
  endpoint  = "security-alerts@example.com" # Replace with actual email
}

resource "aws_cloudwatch_metric_alarm" "db_cpu_utilization" {
  alarm_name          = "${var.environment}-HighDBCPUUtilization"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "This alarm monitors DB CPU utilization for ${var.environment}-customer-db."
  alarm_actions       = [aws_sns_topic.critical_alarms_topic.arn]
  ok_actions          = [aws_sns_topic.critical_alarms_topic.arn]
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.customer_data.id
  }

  tags = {
    Name = "${var.environment}-db-cpu-alarm"
  }
}

# Additional alarms for other critical metrics should also be added here.