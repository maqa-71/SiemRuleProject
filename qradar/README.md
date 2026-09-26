# QRadar Rules

This directory contains 10 QRadar rule definitions transcribed and normalized from the project owner's supplied design document.

## Current state

- Rules are stored as individual JSON files under `qradar/rules/`.
- GitHub Actions validates JSON structure and basic AQL shape only.
- No QRadar host, API key, SEC token, or deployment secret is configured.
- No rule has been deployed to or validated in a QRadar lab.

Before deployment, the QRadar version, DSM mappings, QIDs, custom properties, reference sets, AQL field names, CRE tests, offense indexing, response limiters and performance must be confirmed.
