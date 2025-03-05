# main.tf - Patch Corp's insecure infrastructure blueprint

provider "aws" {
  region = "us-east-1"
}

# Vulnerable EC2 instance using an outdated AMI
resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"  # Insecure/outdated AMI
  instance_type = "t2.micro"
  security_groups = [aws_security_group.open_sg.name]
}

# Overly permissive security group
resource "aws_security_group" "open_sg" {
  name        = "open_sg"
  description = "Security group with overly open inbound rules"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Allows traffic from anywhere
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Public and unencrypted S3 bucket
resource "aws_s3_bucket" "patch_bucket" {
  bucket        = "patchcorp-bucket"
  acl           = "public-read"  # Publicly accessible
  force_destroy = true

  versioning {
    enabled = false  # Versioning disabled
  }
}

# IAM role with overly permissive assume policy
resource "aws_iam_role" "vulnerable_role" {
  name = "vulnerable_role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": { "Service": "ec2.amazonaws.com" },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

# IAM policy with wildcard permissions
resource "aws_iam_policy" "vulnerable_policy" {
  name   = "vulnerable_policy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",  # Overly permissive actions
      "Resource": "*"  # Applies to all resources
    }
  ]
}
EOF
}
