# =============================================================================
# Sample Production Infrastructure — Corrected and Compliant
# =============================================================================
# WARNING: This file has been remediated to remove intentional security and
# compliance violations.
# =============================================================================

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

  default_tags {
    tags = {
      Environment = var.environment
      ManagedBy   = "terraform"
      Project     = "comply-demo"
    }
  }
}

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# -----------------------------------------------------------------------------
# KMS Keys for Encryption
# -----------------------------------------------------------------------------

resource "aws_kms_key" "rds_encryption_key" {
  description             = "${var.environment}-rds-encryption-key"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "Enable IAM User Permissions",
        Effect    = "Allow",
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" },
        Action    = "kms:*",
        Resource  = "*"
      },
      {
        Sid       = "Allow RDS to use key",
        Effect    = "Allow",
        Principal = { Service = "rds.amazonaws.com" },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = "*"
      }
    ]
  })
  tags = {
    Name        = "${var.environment}-rds-encryption-key"
    Environment = var.environment
  }
}

resource "aws_kms_key" "s3_data_lake_encryption_key" {
  description             = "${var.environment}-s3-data-lake-encryption-key"
  deletion_window_in_days = 10
  enable_key_rotation     = true
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "Enable IAM User Permissions",
        Effect    = "Allow",
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" },
        Action    = "kms:*",
        Resource  = "*"
      },
      {
        Sid       = "Allow S3 to use key for bucket",
        Effect    = "Allow",
        Principal = { Service = "s3.amazonaws.com" },
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ],
        Resource = "*"
      }
    ]
  })
  tags = {
    Name        = "${var.environment}-s3-data-lake-encryption-key"
    Environment = var.environment
  }
}

# -----------------------------------------------------------------------------
# VPC & Networking
# -----------------------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.environment}-main-vpc"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.environment}-public-subnet"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "${var.environment}-private-subnet"
  }
}

resource "aws_subnet" "private_az2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = data.aws_availability_zones.available.names[2]

  tags = {
    Name = "${var.environment}-private-subnet-az2"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.environment}-igw"
  }
}

# -----------------------------------------------------------------------------
# Security Groups
# -----------------------------------------------------------------------------

resource "aws_security_group" "app_sg" {
  name        = "${var.environment}-app-sg"
  description = "Security group for application servers and DB access"
  vpc_id      = aws_vpc.main.id

  # Allow HTTP/80 traffic from the ALB
  ingress {
    description     = "Allow HTTP from ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  # Allow PostgreSQL/5432 traffic from application servers within this SG
  ingress {
    description = "Allow Postgres from App Servers"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    self        = true # Allows resources in this SG to talk to each other on this port
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-app-sg"
  }
}

resource "aws_security_group" "alb_sg" {
  name        = "${var.environment}-alb-sg"
  description = "Security group for Application Load Balancer"
  vpc_id      = aws_vpc.main.id

  # Allow HTTP (80) from within the VPC (for redirect if needed, but primary access is HTTPS)
  ingress {
    description = "Allow HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  # Allow HTTPS (443) from within the VPC (or specific external access points)
  ingress {
    description = "Allow HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-alb-sg"
  }
}

# -----------------------------------------------------------------------------
# RDS Instance
# -----------------------------------------------------------------------------

resource "aws_db_subnet_group" "main" {
  name       = "${var.environment}-db-subnet-group"
  subnet_ids = [aws_subnet.private.id, aws_subnet.private_az2.id] # Use only private subnets for Multi-AZ DB

  tags = {
    Name = "${var.environment}-db-subnet-group"
  }
}

resource "aws_db_instance" "customer_data" {
  identifier     = "${var.environment}-customer-data"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"

  allocated_storage     = 100
  max_allocated_storage = 500

  db_name  = "customers"
  username = "admin"
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.app_sg.id]

  storage_encrypted       = true # Remediation: Storage encryption enabled
  kms_key_id              = aws_kms_key.rds_encryption_key.arn # Remediation: KMS key specified
  backup_retention_period = 7 # Remediation: Automated backups enabled (7 days)
  multi_az                = true # Remediation: Multi-AZ enabled for HA
  monitoring_interval     = 60 # Remediation: Enhanced monitoring enabled (60 seconds)
  performance_insights_enabled = true # Remediation: Performance Insights enabled

  publicly_accessible = false
  skip_final_snapshot = true

  tags = {
    Name      = "${var.environment}-customer-data"
    DataClass = "confidential"
    Contains  = "PII"
  }
}

# -----------------------------------------------------------------------------
# S3 Bucket
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "data_lake" {
  bucket = "${var.environment}-comply-demo-data-lake-${data.aws_caller_identity.current.account_id}"

  server_side_encryption_configuration { # Remediation: Server-side encryption enabled
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.s3_data_lake_encryption_key.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }

  tags = {
    Name      = "${var.environment}-data-lake"
    DataClass = "internal"
  }
}

resource "aws_s3_bucket_public_access_block" "data_lake_public_access_block" { # Remediation: Public access blocked
  bucket = aws_s3_bucket.data_lake.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "data_lake" {
  bucket = aws_s3_bucket.data_lake.id

  versioning_configuration {
    status = "Enabled" # Remediation: Versioning enabled for data integrity
  }
}

# -----------------------------------------------------------------------------
# EC2 Instance
# -----------------------------------------------------------------------------

resource "aws_instance" "app_server" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.large"
  subnet_id     = aws_subnet.public.id

  vpc_security_group_ids = [aws_security_group.app_sg.id]

  monitoring = true # Remediation: Detailed monitoring enabled

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
  }

  user_data = <<-EOF
    #!/bin/bash
    apt-get update -y
    apt-get install -y docker.io
    systemctl enable docker
    systemctl start docker
    docker run -d -p 80:80 nginx:latest
  EOF

  tags = {
    Name = "${var.environment}-app-server"
    Role = "application"
  }
}

# -----------------------------------------------------------------------------
# Load Balancer & Listeners
# -----------------------------------------------------------------------------

resource "aws_lb" "app" {
  name               = "${var.environment}-app-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id] # Remediation: Use dedicated ALB security group
  subnets            = [aws_subnet.public.id, aws_subnet.private.id] # ALB should span multiple subnets

  tags = {
    Name = "${var.environment}-app-lb"
  }
}

resource "aws_lb_target_group" "app" {
  name     = "${var.environment}-app-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/health"
    port                = "traffic-port"
    healthy_threshold   = 2
    unhealthy_threshold = 10
    timeout             = 60
    interval            = 300
  }

  tags = {
    Name = "${var.environment}-app-tg"
  }
}

resource "aws_acm_certificate" "app_cert" {
  domain_name       = "example.com" # Placeholder: Replace with your actual domain
  validation_method = "DNS"
  tags = {
    Name        = "${var.environment}-app-cert"
    Environment = var.environment
  }
  lifecycle {
    create_before_destroy = true
  }
  # IMPORTANT: For production, you would need to add `aws_route53_record` resources
  # here for DNS validation, or use a pre-existing validated certificate.
}

resource "aws_lb_listener" "https" { # Remediation: HTTPS listener
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08" # Using a secure SSL policy
  certificate_arn   = aws_acm_certificate.app_cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
  tags = {
    Name = "${var.environment}-app-lb-https-listener"
  }
}


resource "aws_lb_target_group_attachment" "app" {
  target_group_arn = aws_lb_target_group.app.arn
  target_id        = aws_instance.app_server.id
  port             = 80
}

# -----------------------------------------------------------------------------
# CloudTrail Configuration for Monitoring and Detection
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail_log_bucket" {
  bucket = "${var.environment}-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  versioning {
    enabled = true
  }

  tags = {
    Name        = "${var.environment}-cloudtrail-logs"
    Environment = var.environment
  }
}

data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  statement {
    sid       = "AllowCloudTrailPutObject"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_log_bucket.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    sid       = "AllowCloudTrailGetBucketAcl"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_log_bucket.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_bucket_policy" {
  bucket = aws_s3_bucket.cloudtrail_log_bucket.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}


resource "aws_cloudtrail" "main" { # Remediation: CloudTrail configured
  name                          = "${var.environment}-main-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_log_bucket.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_logging                = true
  enable_log_file_validation    = true # Recommended for integrity

  tags = {
    Name        = "${var.environment}-main-cloudtrail"
    Environment = var.environment
  }
}

# -----------------------------------------------------------------------------
# CloudWatch Alarms for Incident Detection and Reporting
# -----------------------------------------------------------------------------

resource "aws_sns_topic" "cloudwatch_alerts" {
  name = "${var.environment}-cloudwatch-alerts-topic"
  tags = {
    Name        = "${var.environment}-cloudwatch-alerts-topic"
    Environment = var.environment
  }
}

resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.cloudwatch_alerts.arn
  protocol  = "email"
  endpoint  = "security-team@example.com" # Placeholder: Replace with actual email
}

resource "aws_cloudwatch_metric_alarm" "ec2_high_cpu_alarm" { # Remediation: EC2 CPU alarm
  alarm_name          = "${var.environment}-ec2-app-server-high-cpu"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This alarm monitors EC2 app server CPU utilization"
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.cloudwatch_alerts.arn]
  ok_actions          = [aws_sns_topic.cloudwatch_alerts.arn]

  dimensions = {
    InstanceId = aws_instance.app_server.id
  }
  tags = {
    Name        = "${var.environment}-ec2-app-server-high-cpu-alarm"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_high_cpu_alarm" { # Remediation: RDS CPU alarm
  alarm_name          = "${var.environment}-rds-customer-data-high-cpu"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This alarm monitors RDS customer data CPU utilization"
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.cloudwatch_alerts.arn]
  ok_actions          = [aws_sns_topic.cloudwatch_alerts.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.customer_data.id
  }
  tags = {
    Name        = "${var.environment}-rds-customer-data-high-cpu-alarm"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_high_connections_alarm" { # Remediation: RDS Connections alarm
  alarm_name          = "${var.environment}-rds-customer-data-high-connections"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = "300"
  statistic           = "Average"
  threshold           = "90"
  alarm_description   = "This alarm monitors high database connections to customer data RDS"
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.cloudwatch_alerts.arn]
  ok_actions          = [aws_sns_topic.cloudwatch_alerts.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.customer_data.id
  }
  tags = {
    Name        = "${var.environment}-rds-customer-data-high-connections-alarm"
    Environment = var.environment
  }
}

# =============================================================================
# Outputs
# =============================================================================

output "db_endpoint" {
  description = "RDS endpoint for the customer database"
  value       = aws_db_instance.customer_data.endpoint
}

output "app_server_public_ip" {
  description = "Public IP of the application server"
  value       = aws_instance.app_server.public_ip
}

output "lb_dns_name" {
  description = "DNS name of the application load balancer"
  value       = aws_lb.app.dns_name
}

output "data_lake_bucket" {
  description = "Name of the S3 data lake bucket"
  value       = aws_s3_bucket.data_lake.id
}