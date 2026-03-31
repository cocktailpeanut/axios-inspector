# Axios Inspector

Axios Inspector is a Bash-based indicator-of-compromise sweep for the March 30-31, 2026 malicious `axios` npm releases. It can run as a standalone script against any root path, and the bundled Pinokio launcher simply calls that script for Pinokio home.

## What It Checks

- Local `node_modules/plain-crypto-js` directories under the selected scan root
- Installed `axios` package manifests under the selected scan root that mention `1.14.1` or `0.30.4`
- Lockfiles under the selected scan root that still reference `plain-crypto-js`
- Platform-specific RAT artifact paths reported by current incident research
- Globally installed `axios` packages that match `1.14.1` or `0.30.4`

## Main Use Case: Bash

Run the scanner directly and pass the root path you want to inspect:

```bash
bash ./scan.sh /path/to/scan
```

Notes:

- The first argument is the scan root.
- If you omit the argument, the script falls back to the current directory.
- Each section shows a live spinner while it runs and then prints either `[match]` with findings or `[clear] none found`.

## Check for Pinokio

If you want to scan Pinokio-managed content specifically:

1. Open the app in Pinokio.
2. Click `Scan`.
3. The launcher passes Pinokio home to `scan.sh` via `{{kernel.homedir}}`.

The launcher uses Bash explicitly, including on Windows, so the same script stays reusable inside and outside Pinokio.

This is a quick IOC sweep, not a full forensic guarantee. A clean result does not prove the machine is clean if malicious packages were already removed, installed outside the selected scan root, or executed long enough to drop additional payloads not covered by the known public indicators.

## Programmatic Access

This project does not expose an HTTP API. Its main feature is the shell-based IOC scan.

### JavaScript

```javascript
import { execFile } from "node:child_process";
import path from "node:path";

const pinokioHome = path.resolve(process.cwd(), "..", "..");

execFile("bash", ["./scan.sh", pinokioHome], (error, stdout, stderr) => {
  console.log({ error, stdout, stderr });
});
```

### Python

```python
import subprocess
from pathlib import Path

pinokio_home = Path.cwd().resolve().parents[1]

result = subprocess.run(
    ["bash", "./scan.sh", str(pinokio_home)],
    capture_output=True,
    text=True,
)
print(result.stdout)
```

### Curl

There is no `curl` example because this launcher does not start a web server or expose an HTTP endpoint.
