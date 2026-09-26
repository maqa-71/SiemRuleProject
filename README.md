# SIEM Rule Project

Detection-as-Code repository for professional Splunk and IBM QRadar detection content.

## Goal

Rules will be managed in GitHub as the source of truth and later validated and deployed to Splunk and QRadar through API-based automation.

## Repository structure

```text
.github/workflows/   CI/CD workflows (added after API design is confirmed)
rules/splunk/        Splunk rule definitions
rules/qradar/        IBM QRadar rule definitions
rules/sigma/         Original Sigma rules and references
scripts/             Validation, conversion and deployment scripts
tests/               Static and regression tests
docs/                Architecture, rule catalog and test evidence
```

## Planned workflow

1. Select and review one Sigma or custom detection idea.
2. Preserve source attribution and MITRE ATT&CK context.
3. Create the Splunk or QRadar implementation.
4. Validate syntax and field mappings.
5. Test in the authorized lab.
6. Tune false positives and document evidence.
7. Deploy through the SIEM API only after validation.

> No detection rules have been added yet. Rules will be implemented and reviewed one at a time.

## Security

Never commit API tokens, passwords, private keys, real customer logs, public IP addresses, or other sensitive environment data. Use GitHub Actions Secrets for credentials.
