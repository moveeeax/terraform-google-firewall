# Changelog

All notable changes to this module are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.2.0] - 2026-11-08

### Added

- `source_tags`, `source_service_accounts` and `target_service_accounts`
  inputs, so ingress rules can be scoped by network tag or service account
  instead of a CIDR. All default to `[]` and are sent as null when empty, so
  existing rules plan unchanged.
- Plan-time checks: a rule cannot mix network tags with service accounts,
  `source_tags` and `source_service_accounts` are rejected on `EGRESS` rules,
  and service account entries must look like an email address.

### Changed

- The `INGRESS` source check now accepts `source_ranges`, `source_tags` or
  `source_service_accounts`; previously only `source_ranges` satisfied it.
- CI: bump actions to their current majors, pin tool versions, and restrict the
  workflow token to `contents: read`.
- CI: add Dependabot for GitHub Actions and the Terraform provider.
- Docs: pin the README usage `source` to a release tag; fix the LICENSE year.

## [1.0.0]

Initial release (`v0.1.0` points at the same commit).

[Unreleased]: https://github.com/moveeeax/terraform-google-firewall/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/moveeeax/terraform-google-firewall/compare/v1.1.0...v1.2.0
[1.0.0]: https://github.com/moveeeax/terraform-google-firewall/releases/tag/v1.0.0
