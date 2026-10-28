package terraform

import (
	"testing"

	"github.com/Idris1980/lookfirst/internal/source"
)

func TestAWSRules(t *testing.T) {
	tf := `
resource "aws_s3_bucket" "site" { bucket = "my-site" }

resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject", Resource = "${aws_s3_bucket.site.arn}/*" }]
  })
}

data "aws_iam_policy_document" "all" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}
resource "aws_iam_policy" "all" { policy = data.aws_iam_policy_document.all.json }

resource "aws_iam_role" "app" {
  assume_role_policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}
resource "aws_iam_role_policy" "inline" {
  role   = aws_iam_role.app.id
  policy = <<EOF
{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
EOF
}
resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_lambda_function" "api" { function_name = "api" }
resource "aws_lambda_function_url" "api" {
  function_name      = aws_lambda_function.api.function_name
  authorization_type = "NONE"
}
resource "aws_lambda_permission" "any" {
  function_name = aws_lambda_function.api.function_name
  principal     = "*"
}

resource "aws_security_group" "web" { name = "web" }
resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  security_group_id = aws_security_group.web.id
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_lb_listener" "plain" { protocol = "HTTP" }
resource "aws_lb_listener" "redirect" {
  protocol = "HTTP"
  default_action { type = "redirect" }
}

resource "aws_eks_cluster" "open" {
  vpc_config { subnet_ids = [] }
}
resource "aws_eks_cluster" "closed" {
  vpc_config { endpoint_public_access = false }
}

resource "aws_db_instance" "db" { storage_encrypted = false }
`
	g := Read([]source.File{{Path: "main.tf", Kind: source.Terraform, Data: []byte(tf)}})
	got := map[string][]string{}
	for _, f := range g.Findings {
		got[f.Title] = append(got[f.Title], f.NodeID)
	}
	want := map[string][]string{
		"Anyone can access it":                           {"aws_s3_bucket_policy.site"},
		"Full control of the AWS account":                {"aws_iam_role.app"},
		"Function is open on the internet without login": {"aws_lambda_function_url.api"},
		"Anyone can call the function":                   {"aws_lambda_function.api"},
		"SSH (port 22) is open to the internet":          {"aws_security_group.web"},
		"No HTTPS":                                       {"aws_lb_listener.plain"},
		"Kubernetes API is reachable from the internet":  {"aws_eks_cluster.open"},
		"Data is not encrypted":                          {"aws_db_instance.db"},
	}
	for title, nodes := range want {
		if len(got[title]) != len(nodes) || got[title][0] != nodes[0] {
			t.Errorf("%q on %v, want %v", title, got[title], nodes)
		}
	}
	// Two policies allow everything: the data document and the heredoc.
	if n := len(got["Permission to do everything"]); n != 2 {
		t.Errorf("%d policies allowing everything, want 2: %v", n, got["Permission to do everything"])
	}
}
