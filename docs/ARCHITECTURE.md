# ATLAS Architecture

ATLAS is designed as a modular platform for discovering, mapping, analysing, and prioritising the exposure of authorised digital assets.

## Logical workflow

```text
User browser
  -> Flask dashboard and authentication
  -> Application routes and scan orchestration
  -> Scope validation and authorisation controls
  -> Discovery -> Port scanning -> Service enumeration
  -> Technology fingerprinting + vulnerability intelligence
  -> Attack surface mapping + topology + exposure analysis
  -> Risk scoring and prioritisation
  -> Database persistence -> Dashboard and reports
```

## Module responsibilities
- `dashboard/`: user interface, routes, and authentication.
- `discovery/`: authorised host and asset discovery.
- `scanner/`: port and network scanning.
- `enumeration/`: service and version enumeration.
- `intelligence/`: technology fingerprinting and vulnerability correlation.
- `attack_surface/`: mapping, topology, asset relationships, and exposure analysis.
- `risk_engine/`: risk scoring and prioritisation.
- `database/`: data models and persistence.
- `reports/`: report generation.
- `tests/`: automated tests.
- `docs/`: scope, inventories, risk, remediation, and architecture documentation.

## Deployment direction (planned)
A public web interface should communicate with a secured backend. Run long-lived Nmap jobs in a controlled worker environment rather than a short-lived serverless web request. Use persistent production storage. Enforce authentication, explicit target authorisation, scope validation, rate limits, audit logging, and safe job execution.

This document describes the proposed architecture; update it as implementation decisions are verified.
