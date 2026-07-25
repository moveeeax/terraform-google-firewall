terraform {
  required_version = ">= 1.5"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_compute_network" "example" {
  project                 = var.project_id
  name                    = "example-fw-network"
  auto_create_subnetworks = false
}

module "firewall" {
  source = "../.."

  project_id  = var.project_id
  name        = "example-allow-ssh"
  network     = google_compute_network.example.self_link
  direction   = "INGRESS"
  description = "SSH from Identity-Aware Proxy TCP forwarding only."

  allow = {
    tcp = ["22"]
  }

  # 35.235.240.0/20 is the fixed source range Google Cloud uses for
  # Identity-Aware Proxy TCP forwarding. Reaching SSH this way keeps the rule
  # off the public internet and puts IAM in front of the connection.
  source_ranges = ["35.235.240.0/20"]

  # Without target_tags the rule would apply to every instance in the network.
  target_tags = ["ssh"]

  enable_logging = true
}

variable "project_id" {
  description = "Project ID to deploy the example firewall rule into."
  type        = string
}

variable "region" {
  description = "Region for the google provider."
  type        = string
  default     = "us-central1"
}

output "firewall_id" {
  value = module.firewall.id
}
