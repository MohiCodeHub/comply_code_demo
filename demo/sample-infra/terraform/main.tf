# =============================================================================
# Sample Production Infrastructure
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
# KMS Key for RDS encryption
# -----------------------------------------------------------------------------

resource "aws_kms_key" "db_encryption_key" {
  description             = "${var.environment}-db-encryption-key"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Name        = "${var.environment}-db-encryption-key"
    DataClass   = "confidential"
    Contains    = "PII"
  }
}

# -----------------------------------------------------------------------------
# ACM Certificate for Load Balancer HTTPS
# This requires a domain and DNS validation. For production, replace with
# an actual certificate or a full ACM/Route53 setup.
# -----------------------------------------------------------------------------

resource "aws_acm_certificate" "app_lb_cert" {
  domain_name       = "${var.environment}.comply-demo.example.com" # Replace with your actual domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${var.environment}-app-lb-cert"
  }
}

# Uncomment and configure the following resources for ACM certificate DNS validation:
# data "aws_route53_zone" "primary" {
#   name         = "example.com." # Replace with your actual domain
#   private_zone = false
# }
#
# resource "aws_route53_record" "app_lb_cert_validation" {
#   for_each = {
#     for dvo in aws_acm_certificate.app_lb_cert.domain_validation_options : dvo.domain_name => {
#       name   = dvo.resource_record_name
#       record = dvo.resource_record_value
#       type   = dvo.resource_record_type
#     }
#   }
#
#   allow_overwrite = true
#   name            = each.value.name
#   records         = [each.value.record]
#   ttl             = 60
#   type            = each.value.type
#   zone_id         = data.aws_route53_zone.primary.zone_id
# }
#
# resource "aws_acm_certificate_validation" "app_lb_cert_validation" {
#   certificate_arn         = aws_acm_certificate.app_lb_cert.arn
#   validation_record_fqdns = [for record in aws_route53_record.app_lb_cert_validation : record.fqdn]
# }


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

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.environment}-igw"
  }
}

# -----------------------------------------------------------------------------
# RDS Instance
# -----------------------------------------------------------------------------

resource "aws_db_subnet_group" "main" {
  name       = "${var.environment}-db-subnet-group"
  subnet_ids = [aws_subnet.public.id, aws_subnet.private.id]

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
  vpc_security_group_ids = [aws_security_group.rds_sg.id]

  storage_encrypted       = true
  kms_key_id              = aws_kms_key.db_encryption_key.arn
  backup_retention_period = 7
  multi_az                = true

  publicly_accessible = false
  skip_final_snapshot = true

  tags = {
    Name        = "${var.environment}-customer-data"
    DataClass   = "confidential"
    Contains    = "PII"
  }
}

# -----------------------------------------------------------------------------
# S3 Bucket
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "data_lake" {
  bucket = "${var.environment}-comply-demo-data-lake-${data.aws_caller_identity.current.account_id}"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = {
    Name      = "${var.environment}-data-lake"
    DataClass = "internal"
  }
}

resource "aws_s3_bucket_public_access_block" "data_lake_public_access_block" {
  bucket = aws_s3_bucket.data_lake.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "data_lake" {
  bucket = aws_s3_bucket.data_lake.id

  versioning_configuration {
    status = "Suspended"
  }
}

# -----------------------------------------------------------------------------
# EC2 Instance
# -----------------------------------------------------------------------------

resource "aws_instance" "app_server" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.large"
  subnet_id     = aws_subnet.public.id

  vpc_security_group_ids = [aws_security_group.app_server_sg.id]

  monitoring = true

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
# Security Groups
# -----------------------------------------------------------------------------

resource "aws_security_group" "alb_sg" {
  name        = "${var.environment}-alb-sg"
  description = "Security group for the Application Load Balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]
  }

  ingress {
    description = "Allow HTTP for redirect from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]
  }

  egress {
    description = "Allow all outbound traffic from ALB"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-alb-sg"
  }
}

resource "aws_security_group" "app_server_sg" {
  name        = "${var.environment}-app-server-sg"
  description = "Security group for application servers"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Allow HTTP from Application Load Balancer"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    description = "Allow all outbound traffic from App Servers"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-app-server-sg"
  }
}

resource "aws_security_group" "rds_sg" {
  name        = "${var.environment}-rds-sg"
  description = "Security group for RDS database instance"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Allow PostgreSQL from application servers"
    from_port       = 5432 # Default PostgreSQL port
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_server_sg.id]
  }

  egress {
    description = "Allow all outbound traffic from RDS"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-rds-sg"
  }
}

# -----------------------------------------------------------------------------
# Load Balancer Listener
# -----------------------------------------------------------------------------

resource "aws_lb" "app" {
  name               = "${var.environment}-app-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public.id, aws_subnet.private.id]

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

resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.app_lb_cert.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_target_group_attachment" "app" {
  target_group_arn = aws_lb_target_group.app.arn
  target_id        = aws_instance.app_server.id
  port             = 80
}

# -----------------------------------------------------------------------------
# CloudTrail Configuration
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "comply-demo-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
  acl    = "private"

  versioning {
    enabled = true
  }

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck20150319",
        Effect    = "Allow",
        Principal = { Service = "cloudtrail.amazonaws.com" },
        Action    = "s3:GetBucketAcl",
        Resource  = "arn:aws:s3:::comply-demo-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
      },
      {
        Sid    = "AWSCloudTrailWrite20150319",
        Effect = "Allow",
        Principal = { Service = "cloudtrail.amazonaws.com" },
        Action = "s3:PutObject",
        Resource = "arn:aws:s3:::comply-demo-cloudtrail-logs-${data.aws_caller_identity.current.account_id}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/comply-demo-cloudtrail"
  retention_in_days = 90
}

resource "aws_iam_role" "cloudwatch_cloudtrail" {
  name = "${var.environment}-cloudwatch-cloudtrail-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudwatch_cloudtrail_policy" {
  name = "${var.environment}-cloudwatch-cloudtrail-policy"
  role = aws_iam_role.cloudwatch_cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = [
          "logs:PutLogEvents",
          "logs:CreateLogStream"
        ],
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = "${var.environment}-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_logging                = true

  cloud_watch_logs_group_arn = aws_cloudwatch_log_group.cloudtrail.arn
  cloud_watch_logs_role_arn  = aws_iam_role.cloudwatch_cloudtrail.arn

  tags = {
    Name = "${var.environment}-cloudtrail"
  }
}

# -----------------------------------------------------------------------------
# CloudWatch Alarms
# -----------------------------------------------------------------------------

resource "aws_sns_topic" "critical_alarms" {
  name = "${var.environment}-critical-infrastructure-alarms"
}

resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.critical_alarms.arn
  protocol  = "email"
  endpoint  = "security-team@example.com" # Replace with actual email
}

resource "aws_cloudwatch_metric_alarm" "high_cpu_app_server" {
  alarm_name          = "${var.environment}-app-server-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "This alarm monitors EC2 CPU utilization"
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.critical_alarms.arn]
  ok_actions          = [aws_sns_topic.critical_alarms.arn]

  dimensions = {
    InstanceId = aws_instance.app_server.id
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_low_free_storage" {
  alarm_name          = "${var.environment}-customer-data-low-free-storage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 1
  metric_name         = "FreeStorageSpace"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Minimum"
  threshold           = 10000000000 # 10 GB
  alarm_description   = "This alarm monitors RDS free storage space"
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.critical_alarms.arn]
  ok_actions          = [aws_sns_topic.critical_alarms.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.customer_data.id
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