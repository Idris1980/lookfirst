# An EC2 server with a database and a bucket. The access key is AWS's own
# documented example key, not a real one.

provider "aws" {
  region     = "eu-north-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "web" {
  key_name   = "web-key"
  public_key = tls_private_key.ssh.public_key_openssh
}

resource "aws_instance" "web" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.micro"
  key_name                    = aws_key_pair.web.key_name
  vpc_security_group_ids      = [aws_security_group.web.id]
  associate_public_ip_address = true
}

resource "aws_db_instance" "db" {
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  password               = "changeme123"
  publicly_accessible    = true
  vpc_security_group_ids = [aws_security_group.web.id]
}

resource "aws_s3_bucket" "uploads" {
  bucket = "my-uploads-bucket"
}

resource "aws_s3_bucket_acl" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  acl    = "public-read"
}
