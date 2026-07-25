# Exposure guardrails. Every run here asserts that a dangerous or invalid
# configuration is rejected at plan time rather than reaching the API.

mock_provider "google" {}

variables {
  project_id = "example-project"
  name       = "test-rule"
  network    = "projects/example-project/global/networks/default"
}

run "rejects_world_open_ssh" {
  command = plan

  variables {
    allow         = { tcp = ["22"] }
    source_ranges = ["0.0.0.0/0"]
  }

  expect_failures = [google_compute_firewall.this]
}

run "rejects_world_open_rdp_over_ipv6" {
  command = plan

  variables {
    allow         = { tcp = ["3389"] }
    source_ranges = ["::/0"]
  }

  expect_failures = [google_compute_firewall.this]
}

run "rejects_world_open_port_range_covering_ssh" {
  command = plan

  variables {
    allow         = { tcp = ["20-30"] }
    source_ranges = ["0.0.0.0/0"]
  }

  expect_failures = [google_compute_firewall.this]
}

run "rejects_world_open_all_ports" {
  command = plan

  variables {
    allow         = { tcp = [] }
    source_ranges = ["0.0.0.0/0"]
  }

  expect_failures = [google_compute_firewall.this]
}

run "rejects_world_open_database_port" {
  command = plan

  variables {
    allow         = { tcp = ["5432"] }
    source_ranges = ["0.0.0.0/0"]
  }

  expect_failures = [google_compute_firewall.this]
}

run "allows_world_open_ssh_when_opted_in" {
  variables {
    allow                    = { tcp = ["22"] }
    source_ranges            = ["0.0.0.0/0"]
    allow_public_admin_ports = true
  }

  assert {
    condition     = contains(google_compute_firewall.this.source_ranges, "0.0.0.0/0")
    error_message = "An explicit opt-in should let the world-open rule through."
  }
}

run "allows_world_open_https" {
  variables {
    allow         = { tcp = ["80", "443"] }
    source_ranges = ["0.0.0.0/0"]
  }

  assert {
    condition     = contains(google_compute_firewall.this.source_ranges, "0.0.0.0/0")
    error_message = "Public web ports are not administration ports and must not need an opt-in."
  }
}

run "allows_world_open_icmp" {
  variables {
    allow         = { icmp = [] }
    source_ranges = ["0.0.0.0/0"]
  }

  assert {
    condition     = one(google_compute_firewall.this.allow).protocol == "icmp"
    error_message = "icmp carries no ports, so it must not trip the restricted-port guardrail."
  }
}

run "allows_ssh_from_iap_range" {
  variables {
    allow         = { tcp = ["22"] }
    source_ranges = ["35.235.240.0/20"]
  }

  assert {
    condition     = contains(google_compute_firewall.this.source_ranges, "35.235.240.0/20")
    error_message = "SSH from the IAP TCP forwarding range is the recommended pattern and must be allowed."
  }
}

run "rejects_ingress_without_source_ranges" {
  command = plan

  variables {
    allow = { tcp = ["443"] }
  }

  expect_failures = [google_compute_firewall.this]
}

run "rejects_source_ranges_on_egress" {
  command = plan

  variables {
    direction     = "EGRESS"
    allow         = { tcp = ["443"] }
    source_ranges = ["10.0.0.0/8"]
  }

  expect_failures = [google_compute_firewall.this]
}

run "rejects_allow_and_deny_together" {
  command = plan

  variables {
    allow         = { tcp = ["443"] }
    deny          = { tcp = ["25"] }
    source_ranges = ["10.0.0.0/8"]
  }

  expect_failures = [google_compute_firewall.this]
}

run "rejects_rule_with_neither_allow_nor_deny" {
  command = plan

  variables {
    source_ranges = ["10.0.0.0/8"]
  }

  expect_failures = [google_compute_firewall.this]
}

run "rejects_invalid_direction" {
  command = plan

  variables {
    direction     = "BOTH"
    allow         = { tcp = ["443"] }
    source_ranges = ["10.0.0.0/8"]
  }

  expect_failures = [var.direction]
}

run "rejects_out_of_range_priority" {
  command = plan

  variables {
    priority      = 70000
    allow         = { tcp = ["443"] }
    source_ranges = ["10.0.0.0/8"]
  }

  expect_failures = [var.priority]
}

run "rejects_malformed_port" {
  command = plan

  variables {
    allow         = { tcp = ["https"] }
    source_ranges = ["10.0.0.0/8"]
  }

  expect_failures = [var.allow]
}

run "rejects_malformed_cidr" {
  command = plan

  variables {
    allow         = { tcp = ["443"] }
    source_ranges = ["10.0.0.0"]
  }

  expect_failures = [var.source_ranges]
}
