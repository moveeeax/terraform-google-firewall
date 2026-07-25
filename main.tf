locals {
  # Only these protocols carry port numbers. icmp, esp, ah and ipip ignore the
  # ports field entirely, so an "empty ports" list on them does not mean
  # "every port".
  port_bearing_protocols = ["tcp", "udp", "sctp", "all"]

  # CIDRs that mean "reachable from the entire internet".
  world_open_cidrs = ["0.0.0.0/0", "::/0"]

  is_world_open_ingress = var.direction == "INGRESS" && length(
    setintersection(toset(var.source_ranges), toset(local.world_open_cidrs))
  ) > 0

  # Remote administration and datastore ports. Reaching any of these from the
  # internet is almost always a mistake, so it needs an explicit opt-in.
  restricted_ports = {
    "22"    = "SSH"
    "1433"  = "MSSQL"
    "1521"  = "Oracle"
    "2375"  = "Docker daemon"
    "2376"  = "Docker daemon (TLS)"
    "3306"  = "MySQL"
    "3389"  = "RDP"
    "5432"  = "PostgreSQL"
    "5900"  = "VNC"
    "5985"  = "WinRM"
    "5986"  = "WinRM (HTTPS)"
    "6379"  = "Redis"
    "9042"  = "Cassandra"
    "9200"  = "Elasticsearch"
    "11211" = "Memcached"
    "27017" = "MongoDB"
  }

  # Every port opened by var.allow, normalised to from/to ranges. An empty
  # ports list on a port-bearing protocol means "all ports" in Google Cloud.
  allowed_port_ranges = flatten([
    for protocol, ports in var.allow : [
      for port in(length(ports) > 0 ? ports : ["0-65535"]) : {
        from = tonumber(split("-", port)[0])
        to   = tonumber(split("-", port)[length(split("-", port)) - 1])
      }
    ] if contains(local.port_bearing_protocols, lower(protocol))
  ])

  exposed_restricted_ports = [
    for port, label in local.restricted_ports : "${port} (${label})"
    if anytrue([
      for range in local.allowed_port_ranges :
      tonumber(port) >= range.from && tonumber(port) <= range.to
    ])
  ]
}

resource "google_compute_firewall" "this" {
  project     = var.project_id
  name        = var.name
  network     = var.network
  direction   = var.direction
  priority    = var.priority
  description = var.description

  source_ranges      = length(var.source_ranges) > 0 ? var.source_ranges : null
  destination_ranges = length(var.destination_ranges) > 0 ? var.destination_ranges : null
  target_tags        = length(var.target_tags) > 0 ? var.target_tags : null

  dynamic "allow" {
    for_each = var.allow
    content {
      protocol = allow.key
      # An empty list must be sent as null, not [], so that Google Cloud reads
      # it as "every port" instead of producing a permanent diff.
      ports = length(allow.value) > 0 ? allow.value : null
    }
  }

  dynamic "deny" {
    for_each = var.deny
    content {
      protocol = deny.key
      ports    = length(deny.value) > 0 ? deny.value : null
    }
  }

  dynamic "log_config" {
    for_each = var.enable_logging ? [1] : []
    content {
      metadata = var.log_metadata
    }
  }

  lifecycle {
    # A Google Cloud firewall rule is either an allow rule or a deny rule.
    precondition {
      condition     = (length(var.allow) > 0) != (length(var.deny) > 0)
      error_message = "Exactly one of `allow` or `deny` must be set: a Google Cloud firewall rule is either an allow rule or a deny rule, never both and never neither."
    }

    # Google Cloud treats an INGRESS rule with no source as 0.0.0.0/0. This
    # module does not expose source_tags or source_service_accounts, so
    # source_ranges is the only way to scope an ingress rule.
    precondition {
      condition     = var.direction != "INGRESS" || length(var.source_ranges) > 0
      error_message = "`source_ranges` must be set for INGRESS rules; an ingress rule with no source applies to every source address on the internet."
    }

    # The source of an EGRESS rule is always the instance itself; Google Cloud
    # rejects sourceRanges on egress rules.
    precondition {
      condition     = var.direction != "EGRESS" || length(var.source_ranges) == 0
      error_message = "`source_ranges` cannot be used on EGRESS rules; scope the destination with `destination_ranges` instead."
    }

    # The guardrail: no world-open administration or datastore ports unless the
    # caller says so on purpose.
    precondition {
      condition     = var.allow_public_admin_ports || !local.is_world_open_ingress || length(local.exposed_restricted_ports) == 0
      error_message = "Firewall rule `${var.name}` allows ${join(", ", local.exposed_restricted_ports)} from ${join(" and ", var.source_ranges)}. Restrict `source_ranges` (for SSH, Google Cloud IAP TCP forwarding uses 35.235.240.0/20), or set `allow_public_admin_ports = true` if this exposure is intentional."
    }
  }
}
