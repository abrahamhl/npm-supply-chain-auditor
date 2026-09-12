# Systems Architecture Audit

## Perspective: Principal Architect
**Focus:** Rule engines, data decoupling, SIEM integration.

### Findings
1. **Decoupling:** Moving from hardcoded arrays to ioc_dataset.json allows out-of-band threat intel updates.
2. **Output Format:** The JSON report schema is easily ingested by Splunk/ELK.

### Action Items
- [x] Enforced structured JSON payload outputs.
