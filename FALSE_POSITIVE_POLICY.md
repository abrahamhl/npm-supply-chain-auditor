# False Positive Policy

Security tools lose value when false positives train operators to ignore them. Alert fatigue is the primary reason post-incident sweeps fail. 

## The Policy
1. **Size Constraints:** We do not flag generic names like `setup.mjs` unless they match the exact byte-size of the known malicious payload (when applicable), or exist inside a confirmed vulnerable path.
2. **Explicit Allowlisting:** The `$Benign` array in our IOC dataset contains path substrings that are known to collide with our heuristics (e.g., `\node_modules\motion-dom\`, `\anaconda3\pkgs\`). If a file matches an IOC but falls inside an allowlisted path, it is reported as `INFO` and ignored during remediation.
3. **Prerequisite Gating:** The primary indicator of this malware family is the downloading of the `bun` runtime on machines that do not normally use it. If `bun` is entirely absent from the system, the scanner downgrades confidence on isolated file-name matches, as the payload could not have successfully executed.
