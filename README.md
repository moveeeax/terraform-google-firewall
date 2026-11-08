# terraform-google-firewall

Terraform module that manages a [Google Cloud](https://cloud.google.com/)
VPC firewall rule (`google_compute_firewall`). It supports ingress or egress
direction with allow and deny blocks driven by simple protocol-to-ports maps.

The module refuses, at plan time, to open administration or datastore ports to
the whole internet unless you say so explicitly. See
[Exposure guardrails](#exposure-guardrails).

## Usage

```hcl
module "firewall" {
  source = "github.com/moveeeax/terraform-google-firewall?ref=v1.0.0"

  project_id = var.project_id
  name       = "allow-ssh"
  network    = module.vpc.self_link
  direction  = "INGRESS"

  allow = {
    tcp = ["22"]
  }

  source_ranges = ["10.0.0.0/8"]
  target_tags   = ["ssh"]
}
```

A runnable example lives in [`examples/basic`](examples/basic).

## Exposure guardrails

Firewall rules are the one place where a typo becomes an open door, so the
module rejects the following configurations while planning, before anything
reaches the API:

| Rejected configuration | Why |
|---|---|
| An `allow` rule reaching SSH, RDP, WinRM, VNC, the Docker daemon, or a database/cache port from `0.0.0.0/0` or `::/0` | Remote administration and datastores should never be internet-facing by accident. Port ranges (`"20-30"`) and "all ports" (`tcp = []`) are expanded and checked too. Set `allow_public_admin_ports = true` to override. |
| An `INGRESS` rule with none of `source_ranges`, `source_tags`, `source_service_accounts` | Google Cloud treats an ingress rule with no source as `0.0.0.0/0`. |
| `source_ranges`, `source_tags` or `source_service_accounts` on an `EGRESS` rule | The source of an egress rule is always the instance; Google Cloud rejects these fields. |
| Network tags and service accounts in the same rule | Google Cloud does not allow `source_service_accounts` or `target_service_accounts` together with `source_tags` or `target_tags`. |
| Both `allow` and `deny`, or neither | A Google Cloud firewall rule is either an allow rule or a deny rule. |
| A port that is not a number or a `from-to` range, or a malformed CIDR | Caught by variable validation instead of an opaque API error. |

Two things the module deliberately does **not** decide for you, but you should
know about:

- **`target_tags` and `target_service_accounts` are optional, and leaving both
  empty applies the rule to every instance in the network.** Scope your rules
  whenever you can.
- **`priority` is 0-65535 and lower wins.** A rule at priority 100 beats one at
  priority 1000. At equal priority, `deny` beats `allow`.

For SSH, prefer [Identity-Aware Proxy TCP
forwarding](https://cloud.google.com/iap/docs/using-tcp-forwarding) over a
public rule: allow port 22 from `35.235.240.0/20` only, and let IAM decide who
can connect.

## Scoping by service account or network tag

For east-west traffic between your own instances, scope the rule by identity
instead of by CIDR. Google Cloud recommends service accounts over network tags
for this: anyone who can edit an instance can change its tags, while attaching
a service account needs `iam.serviceAccountUser` on that account.

```hcl
module "app_to_db" {
  source = "github.com/moveeeax/terraform-google-firewall?ref=v1.0.0"

  project_id = var.project_id
  name       = "allow-app-to-postgres"
  network    = module.vpc.self_link

  allow = {
    tcp = ["5432"]
  }

  source_service_accounts = ["app@my-project.iam.gserviceaccount.com"]
  target_service_accounts = ["db@my-project.iam.gserviceaccount.com"]
}
```

Rules for these fields, enforced at plan time:

- Use either tags or service accounts for the whole rule. Google Cloud rejects
  a rule that combines `source_service_accounts` or `target_service_accounts`
  with `source_tags` or `target_tags`.
- `source_tags` and `source_service_accounts` are for `INGRESS` only. Either
  one counts as the source an ingress rule needs, so `source_ranges` becomes
  optional when one of them is set.
- `source_ranges` can be combined with `source_tags` or
  `source_service_accounts`. Google Cloud then matches traffic from either
  source, not both.
- Tag and service account sources match the internal IPs of instances only.
  They do not cover traffic to an instance's external IP.

## Requirements

| Name      | Version  |
|-----------|----------|
| terraform | >= 1.5   |
| google    | >= 5.0   |

The test suite under [`tests/`](tests) additionally needs Terraform or OpenTofu
>= 1.7 for `mock_provider`. The module itself does not.

## Inputs

| Name                       | Description                                                                                          | Type                | Default                    | Required |
|----------------------------|------------------------------------------------------------------------------------------------------|---------------------|----------------------------|:--------:|
| `project_id`               | ID of the project in which to create the firewall rule.                                              | `string`            | n/a                        |   yes    |
| `name`                     | Name of the firewall rule.                                                                           | `string`            | n/a                        |   yes    |
| `network`                  | Self link or name of the VPC network.                                                                | `string`            | n/a                        |   yes    |
| `direction`                | Direction of traffic: INGRESS or EGRESS.                                                             | `string`            | `"INGRESS"`                |    no    |
| `priority`                 | Priority of the rule, 0-65535. Lower wins.                                                           | `number`            | `1000`                     |    no    |
| `allow`                    | Allow rules mapping protocol to ports. Mutually exclusive with `deny`.                               | `map(list(string))` | `{}`                       |    no    |
| `deny`                     | Deny rules mapping protocol to ports. Mutually exclusive with `allow`.                               | `map(list(string))` | `{}`                       |    no    |
| `source_ranges`            | Source CIDR ranges. INGRESS only; an ingress rule needs this, `source_tags` or `source_service_accounts`. | `list(string)` | `[]`                     |    no    |
| `source_tags`              | Network tags of source instances. INGRESS only. Cannot be combined with service accounts.            | `list(string)`      | `[]`                       |    no    |
| `source_service_accounts`  | Service account emails of source instances. INGRESS only. Cannot be combined with network tags.      | `list(string)`      | `[]`                       |    no    |
| `destination_ranges`       | Destination CIDR ranges for EGRESS rules.                                                            | `list(string)`      | `[]`                       |    no    |
| `target_tags`              | Instance network tags the rule applies to. Cannot be combined with service accounts.                 | `list(string)`      | `[]`                       |    no    |
| `target_service_accounts`  | Service account emails of the instances the rule applies to. Cannot be combined with network tags. With `target_tags` also empty, the rule applies to every instance in the network. | `list(string)` | `[]` | no |
| `allow_public_admin_ports` | Opt in to exposing administration or datastore ports to `0.0.0.0/0` or `::/0`.                       | `bool`              | `false`                    |    no    |
| `enable_logging`           | Enable Firewall Rules Logging. Logs go to Cloud Logging and are billed as log volume.                | `bool`              | `false`                    |    no    |
| `log_metadata`             | `INCLUDE_ALL_METADATA` or `EXCLUDE_ALL_METADATA`. Only used when `enable_logging` is true.            | `string`            | `"INCLUDE_ALL_METADATA"`   |    no    |
| `description`              | Optional description for the firewall rule.                                                          | `string`            | `null`                     |    no    |

## Outputs

| Name        | Description                          |
|-------------|--------------------------------------|
| `id`        | Identifier of the firewall rule.    |
| `self_link` | URI of the firewall rule.           |
| `name`      | Name of the firewall rule.          |

## Development

```sh
terraform fmt -recursive
terraform init -backend=false
terraform validate
terraform test          # mocked provider, no credentials needed
```

## License

[MIT](LICENSE)
