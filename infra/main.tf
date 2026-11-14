# Infraestrutura da TaskFlow (EXEMPLO DE ESTUDO).
# Este codigo so e validado e escaneado: nunca rode "terraform apply" daqui.

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
  region = "us-east-1"
}

data "aws_caller_identity" "atual" {}

locals {
  # Falha 1: tags de identificacao, ambiente e dono.
  tags = {
    Projeto  = "taskflow-devsecops"
    Ambiente = "estudo"
    Owner    = "aluno"
  }
}

# Falha 6: o IP do SSH vem de uma variavel, nunca fixo no codigo.
variable "ip_permitido_ssh" {
  description = "CIDR autorizado a acessar o SSH (porta 22). Nunca use 0.0.0.0/0."
  type        = string

  validation {
    condition     = var.ip_permitido_ssh != "0.0.0.0/0"
    error_message = "ip_permitido_ssh nao pode ser 0.0.0.0/0 (SSH aberto para o mundo)."
  }
}

# ------------------------------------------------------------------ chave KMS
# Falha 4: chave gerenciada pelo cliente, com rotacao automatica e politica explicita.
resource "aws_kms_key" "relatorios" {
  description             = "Chave do bucket de relatorios da TaskFlow"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AdministracaoPelaConta"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.atual.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })

  tags = local.tags
}

# ------------------------------------------------------------ bucket de relatorios
resource "aws_s3_bucket" "relatorios" {
  # checkov:skip=CKV_AWS_144: replicacao entre regioes tem custo e nao se justifica num bucket de estudo.
  # checkov:skip=CKV2_AWS_62: sem consumidores de eventos neste laboratorio; notificacoes nao agregam nada.
  bucket = "taskflow-relatorios-estudo"

  tags = local.tags
}

# Falhas 2 e 3: bucket privado. Bloqueia acesso publico e nao usa ACL publica.
resource "aws_s3_bucket_public_access_block" "relatorios" {
  bucket = aws_s3_bucket.relatorios.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "relatorios" {
  bucket = aws_s3_bucket.relatorios.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Falha 4: criptografia em repouso com a chave KMS.
resource "aws_s3_bucket_server_side_encryption_configuration" "relatorios" {
  bucket = aws_s3_bucket.relatorios.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.relatorios.arn
    }
    bucket_key_enabled = true
  }
}

# Falha 5: versionamento (permite recuperar um objeto apagado ou sobrescrito).
resource "aws_s3_bucket_versioning" "relatorios" {
  bucket = aws_s3_bucket.relatorios.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Logging de acesso: os acessos ao bucket de relatorios ficam registrados no bucket de logs.
resource "aws_s3_bucket_logging" "relatorios" {
  bucket        = aws_s3_bucket.relatorios.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "acesso-relatorios/"
}

# Ciclo de vida: versoes antigas expiram e uploads incompletos sao descartados.
resource "aws_s3_bucket_lifecycle_configuration" "relatorios" {
  bucket = aws_s3_bucket.relatorios.id

  rule {
    id     = "expirar-versoes-antigas"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# --------------------------------------------------------------- bucket de logs
# O bucket que recebe os logs de acesso tambem e protegido (privado, versionado, com ciclo de vida).
resource "aws_s3_bucket" "logs" {
  # checkov:skip=CKV_AWS_18: este bucket RECEBE os logs de acesso; ele nao registra o proprio acesso (evitaria um laco).
  # checkov:skip=CKV_AWS_144: replicacao entre regioes tem custo e nao se justifica num bucket de logs de estudo.
  # checkov:skip=CKV_AWS_145: o S3 nao entrega logs de acesso em bucket com SSE-KMS; este bucket usa SSE-S3 (AES256).
  # checkov:skip=CKV2_AWS_62: sem consumidores de eventos neste laboratorio; notificacoes nao agregam nada.
  bucket = "taskflow-relatorios-logs-estudo"

  tags = local.tags
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# O S3 nao entrega logs de acesso em bucket com SSE-KMS; por isso este bucket usa SSE-S3 (AES256).
# trivy:ignore:AVD-AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expirar-logs-antigos"
    status = "Enabled"

    filter {}

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# --------------------------------------------------------------- security group
# O Trivy (AVD-AWS-0104) acusa a saida liberada para qualquer IP. Aceitamos a excecao: a instancia
# precisa alcancar a internet pela porta 443 para baixar atualizacoes, e nao ha uma lista fixa de destinos.
# A saida ja esta limitada a HTTPS (443) e o SSH de entrada e restrito ao IP da variavel.
# trivy:ignore:AVD-AWS-0104
resource "aws_security_group" "app" {
  # checkov:skip=CKV2_AWS_5: security group de exemplo, sem instancia EC2 anexada neste laboratorio.
  name        = "taskflow-app-sg"
  description = "Security group da aplicacao TaskFlow"

  # Falha 6: SSH somente do IP (CIDR) informado na variavel.
  ingress {
    description = "SSH somente do IP autorizado"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ip_permitido_ssh]
  }

  # Falha 7: saida limitada a HTTPS, em vez de todo o trafego.
  # (o destino continua qualquer IP: a instancia precisa baixar atualizacoes pela internet)
  egress {
    description = "Saida apenas HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.tags
}
