# Runs with a mocked provider, so no credentials and no network access are
# needed. `mock_provider` requires Terraform >= 1.7 / OpenTofu >= 1.7 to run the
# tests; the module itself still supports >= 1.5.

mock_provider "google" {}

variables {
  project_id = "example-project"
  name       = "test-rule"
  network    = "projects/example-project/global/networks/default"
}

run "safe_defaults" {
  variables {
    allow         = { tcp = ["22"] }
    source_ranges = ["10.0.0.0/8"]
    target_tags   = ["ssh"]
  }

  assert {
    condition     = google_compute_firewall.this.direction == "INGRESS"
    error_message = "direction should default to INGRESS."
  }

  assert {
    condition     = google_compute_firewall.this.priority == 1000
    error_message = "priority should default to 1000, the Google Cloud default."
  }

  assert {
    condition     = length(google_compute_firewall.this.log_config) == 0
    error_message = "Firewall Rules Logging should stay off unless enable_logging is set."
  }

  assert {
    condition     = length(google_compute_firewall.this.destination_ranges) == 0
    error_message = "destination_ranges should be unset on an ingress rule that does not ask for one."
  }
}

run "empty_lists_are_sent_as_null" {
  variables {
    allow         = { icmp = [] }
    source_ranges = ["10.0.0.0/8"]
  }

  assert {
    condition     = one(google_compute_firewall.this.allow).ports == null
    error_message = "An empty ports list must be sent as null so Google Cloud reads it as 'all ports'."
  }

  assert {
    condition     = google_compute_firewall.this.target_tags == null
    error_message = "An empty target_tags list must be sent as null, not as an empty set."
  }
}

run "logging_can_be_enabled" {
  variables {
    allow          = { tcp = ["443"] }
    source_ranges  = ["10.0.0.0/8"]
    enable_logging = true
    log_metadata   = "EXCLUDE_ALL_METADATA"
  }

  assert {
    condition     = one(google_compute_firewall.this.log_config).metadata == "EXCLUDE_ALL_METADATA"
    error_message = "log_metadata should be passed through to the log_config block."
  }
}

run "egress_rule" {
  variables {
    direction          = "EGRESS"
    deny               = { all = [] }
    destination_ranges = ["0.0.0.0/0"]
    priority           = 65000
  }

  assert {
    condition     = google_compute_firewall.this.source_ranges == null
    error_message = "An egress rule must not carry source_ranges."
  }

  assert {
    condition     = one(google_compute_firewall.this.deny).protocol == "all"
    error_message = "deny blocks should be rendered from the deny map."
  }
}

run "new_scoping_fields_default_to_null" {
  variables {
    allow         = { tcp = ["443"] }
    source_ranges = ["10.0.0.0/8"]
  }

  assert {
    condition     = google_compute_firewall.this.source_tags == null
    error_message = "source_tags must stay unset when not given, so existing rules plan unchanged."
  }

  assert {
    condition     = google_compute_firewall.this.source_service_accounts == null
    error_message = "source_service_accounts must stay unset when not given, so existing rules plan unchanged."
  }

  assert {
    condition     = google_compute_firewall.this.target_service_accounts == null
    error_message = "target_service_accounts must stay unset when not given, so existing rules plan unchanged."
  }
}

run "ingress_scoped_by_service_accounts" {
  variables {
    allow                   = { tcp = ["5432"] }
    source_service_accounts = ["app@example-project.iam.gserviceaccount.com"]
    target_service_accounts = ["db@example-project.iam.gserviceaccount.com"]
  }

  assert {
    condition     = google_compute_firewall.this.source_ranges == null
    error_message = "A service-account-scoped rule must not need source_ranges."
  }

  assert {
    condition     = contains(google_compute_firewall.this.source_service_accounts, "app@example-project.iam.gserviceaccount.com")
    error_message = "source_service_accounts should be passed through."
  }

  assert {
    condition     = contains(google_compute_firewall.this.target_service_accounts, "db@example-project.iam.gserviceaccount.com")
    error_message = "target_service_accounts should be passed through."
  }
}

run "ingress_scoped_by_source_tags" {
  variables {
    allow       = { tcp = ["8080"] }
    source_tags = ["frontend"]
    target_tags = ["backend"]
  }

  assert {
    condition     = contains(google_compute_firewall.this.source_tags, "frontend")
    error_message = "source_tags should be passed through."
  }
}

run "source_ranges_and_service_accounts_together" {
  variables {
    allow                   = { tcp = ["443"] }
    source_ranges           = ["10.10.0.0/16"]
    source_service_accounts = ["app@example-project.iam.gserviceaccount.com"]
  }

  assert {
    condition     = contains(google_compute_firewall.this.source_ranges, "10.10.0.0/16") && length(google_compute_firewall.this.source_service_accounts) == 1
    error_message = "source_ranges and source_service_accounts may be combined; Google Cloud matches either."
  }
}

run "egress_scoped_by_target_service_account" {
  variables {
    direction               = "EGRESS"
    deny                    = { all = [] }
    destination_ranges      = ["0.0.0.0/0"]
    target_service_accounts = ["batch@example-project.iam.gserviceaccount.com"]
  }

  assert {
    condition     = contains(google_compute_firewall.this.target_service_accounts, "batch@example-project.iam.gserviceaccount.com")
    error_message = "target_service_accounts should be usable on egress rules."
  }
}
