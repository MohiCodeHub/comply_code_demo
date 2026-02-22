# Sample Production Infrastructure — Intentionally Non-Compliant
# WARNING: DO NOT deploy this configuration.

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

  storage_encrypted       = false
  backup_retention_period = 0
  multi_az                = false
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
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
