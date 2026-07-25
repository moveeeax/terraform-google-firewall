variable "project_id" {
  description = "ID of the project in which to create the firewall rule."
  type        = string
}

variable "name" {
  description = "Name of the firewall rule."
  type        = string
}

variable "network" {
  description = "Self link or name of the VPC network the rule applies to."
  type        = string
}

variable "direction" {
  description = "Direction of traffic the rule applies to: INGRESS or EGRESS."
  type        = string
  default     = "INGRESS"

  validation {
    condition     = contains(["INGRESS", "EGRESS"], var.direction)
    error_message = "direction must be either INGRESS or EGRESS."
  }
}

variable "priority" {
  description = "Priority of the rule, between 0 and 65535. Lower values take precedence, and a DENY rule beats an ALLOW rule of the same priority."
  type        = number
  default     = 1000

  validation {
    condition     = var.priority >= 0 && var.priority <= 65535
    error_message = "priority must be between 0 and 65535."
  }
}

variable "allow" {
  description = "Allow rules, mapping IP protocol (e.g. tcp) to a list of ports. Ports may be empty for all ports. Mutually exclusive with `deny`."
  type        = map(list(string))
  default     = {}

  validation {
    condition = alltrue([
      for ports in values(var.allow) : alltrue([
        for port in ports : can(regex("^[0-9]{1,5}(-[0-9]{1,5})?$", port))
      ])
    ])
    error_message = "Each entry in allow must be a port number or a port range, e.g. \"22\" or \"8000-8080\"."
  }
}

variable "deny" {
  description = "Deny rules, mapping IP protocol to a list of ports. Mutually exclusive with `allow`."
  type        = map(list(string))
  default     = {}

  validation {
    condition = alltrue([
      for ports in values(var.deny) : alltrue([
        for port in ports : can(regex("^[0-9]{1,5}(-[0-9]{1,5})?$", port))
      ])
    ])
    error_message = "Each entry in deny must be a port number or a port range, e.g. \"22\" or \"8000-8080\"."
  }
}

variable "source_ranges" {
  description = "Source CIDR ranges for INGRESS rules. Required for INGRESS; Google Cloud treats an ingress rule with no source as 0.0.0.0/0."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.source_ranges : can(cidrhost(cidr, 0))])
    error_message = "Every entry in source_ranges must be a valid IPv4 or IPv6 CIDR block, e.g. \"10.0.0.0/8\"."
  }
}

variable "destination_ranges" {
  description = "Destination CIDR ranges for EGRESS rules."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for cidr in var.destination_ranges : can(cidrhost(cidr, 0))])
    error_message = "Every entry in destination_ranges must be a valid IPv4 or IPv6 CIDR block, e.g. \"10.0.0.0/8\"."
  }
}

variable "target_tags" {
  description = "Instance network tags the rule applies to. Empty applies the rule to every instance in the network."
  type        = list(string)
  default     = []
}

variable "allow_public_admin_ports" {
  description = "Opt in to allowing administration or datastore ports (SSH, RDP, WinRM, VNC, Docker, MySQL, PostgreSQL, MSSQL, Oracle, Redis, MongoDB, Cassandra, Elasticsearch, Memcached) from 0.0.0.0/0 or ::/0. Left false, such a rule is rejected at plan time."
  type        = bool
  default     = false
}

variable "enable_logging" {
  description = "Enable Firewall Rules Logging for this rule. Logs are exported to Cloud Logging and are billed as log volume."
  type        = bool
  default     = false
}

variable "log_metadata" {
  description = "How much metadata to include in firewall logs: INCLUDE_ALL_METADATA or EXCLUDE_ALL_METADATA. Only used when `enable_logging` is true."
  type        = string
  default     = "INCLUDE_ALL_METADATA"

  validation {
    condition     = contains(["INCLUDE_ALL_METADATA", "EXCLUDE_ALL_METADATA"], var.log_metadata)
    error_message = "log_metadata must be either INCLUDE_ALL_METADATA or EXCLUDE_ALL_METADATA."
  }
}

variable "description" {
  description = "Optional description for the firewall rule."
  type        = string
  default     = null
}
