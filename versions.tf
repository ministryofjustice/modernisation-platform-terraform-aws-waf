terraform {
  required_providers {
    aws = {
      version = "~> 6.15"
      source  = "hashicorp/aws"
    }
  }
  required_version = ">= 1.0.1"
}
