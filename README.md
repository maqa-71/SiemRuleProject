# SIEM Detection Rules

Detection-as-Code repository for Splunk and IBM QRadar.

## Structure

```text
.github/workflows/
├── deploy_splunk.yml
└── deploy_qradar.yml

splunk/
└── savedsearches.conf

qradar/
└── README.md
```

## Current status

- Splunk: 15 draft saved searches are stored in one `savedsearches.conf` file.
- QRadar: rule content and API deployment are not configured yet.
- Splunk rules are disabled (`enableSched = 0`) until lab validation is completed.

## Workflow

1. Edit rules only in GitHub.
2. Pull requests validate `savedsearches.conf`.
3. Changes merged to `main` are deployed through the Splunk REST API by a self-hosted runner.
4. Do not edit deployed searches directly in Splunk; update the GitHub source instead.

## Required GitHub secrets for Splunk

- `SPLUNK_HOST`
- `SPLUNK_TOKEN`
- `SPLUNK_VERIFY_SSL`

Never commit credentials, tokens, private keys, or sensitive logs.
