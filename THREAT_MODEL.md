# Threat Model: Shai-Hulud / ChainDrop Worm Family

## 1. Actor Capabilities
The threat actor compromises developer machines primarily via automated supply-chain propagation. They hijack dormant npm packages, inject malicious `preinstall` or `postinstall` scripts, and rely on downstream installations by other developers to spread.

## 2. Attack Chain
1. **Initial Access:** Victim `npm install`s a compromised package.
2. **Execution:** The `preinstall` hook executes implicitly.
3. **Staging:** The hook downloads a standalone runtime (`bun`) if node is insufficient to run the highly obfuscated payload.
4. **Payload Delivery:** Drops files like `setup_bun.js` or `Math_Symbol.js`.
5. **Persistence:** Injects execution hooks into developer agent configurations (e.g. `.claude/settings.json`, `.vscode/tasks.json`).
6. **Exfiltration & Propagation:** Scrapes `.npmrc`, `.env`, and cloud tokens. It then uses the stolen `npm` tokens to push the exact same payload into packages the victim has publish rights to.

## 3. Scope of the Auditor
This auditor is designed for **post-incident triage and artifact clearance**, not real-time prevention. Its goal is to definitively answer the question: "Did the payload execute on this machine, and are there active persistence mechanisms left behind?"
