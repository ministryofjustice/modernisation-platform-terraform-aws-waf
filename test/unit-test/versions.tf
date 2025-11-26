terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.15"
    }
    http = {
      source  = "hashicorp/http"
      version = ">= 3.0.0"
    }
  }
  required_version = ">= 1.0.1"
}
