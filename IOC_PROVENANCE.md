# IOC Provenance

Indicators of Compromise (IOCs) are actively sourced and verified against incident reports from primary security vendors and open-source intelligence. 

All IOCs are now stored in `ioc_dataset.json`, completely decoupled from the scanner code. This ensures the dataset can be updated by analysts without modifying the core PowerShell execution logic.

## Provenance Log
- **2026-08-01 (ChainDrop)**: Added `Math_Symbol.js` (727680 bytes) and `math_init.js`. Sourced from Palo Alto Unit 42 and StepSecurity incident disclosures.
- **2025-11-15 (Shai-Hulud 2.0)**: Added `setup_bun.js` and `bun_environment.js`. Sourced from Elastic Security Labs.
- **2025-09-10 (Shai-Hulud)**: Added `truffleSecrets.json` and credential harvester cache `.truffler-cache`.

## Schema
The JSON dataset separates:
- **Factual Data:** Names, hashes, lengths, URLs.
- **Inference/Context:** The campaign name or purpose associated with the IOC.
- **Benign Patterns:** Overrides to explicitly prevent false positives.
