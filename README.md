# finding_secrets

Fast, low-noise triage of hardcoded secrets, tokens and endpoints in **APK**, **IPA** and native binaries.

`find_secrets.sh` unpacks the app, extracts strings from the code, libraries, assets and plists, and ranks what it finds by signal instead of volume. A short text report, a grouped URL list and an optional HTML report come out the other end.

> **For authorized security testing and research only.** Only scan apps you own or have written permission to assess.

## HTML Report Preview

![finding_secrets HTML report preview](docs/report_preview.svg)

> Generated with `-H report.html` from a fictional app. The full interactive report is in [`sample_report.html`](sample_report.html).

## Why

A grep for `password`, `token` and `secret` across an APK returns thousands of lines: UI labels, log messages, class names, SDK constants. When the list is that long, nobody reads it, and the real finding hides in the volume.

This script is built around one rule: **every false positive is a bug in the rules**. It requires a keyword, an assignment and a value that looks like a secret, trusts well-known token formats, decodes JWTs before judging them, validates hosts before listing them, and annotates ambiguous cases instead of hiding them.

It is a triage tool, not a verdict. It tells you where to look. Validation stays human: `openssl`, the provider's API, a real privilege test.

## Features

- **APK, IPA or any binary** as input, with the app's package or bundle ID detected when possible
- **Keyword + assignment + value** rule: the value must end the string and contain a digit or a symbol, so log lines and identifiers do not match
- **Known token formats**: AWS, Google, Stripe, GitHub, Slack, JWT and `PRIVATE KEY` blocks
- **JWT decoding**: shows `alg`, claim names, a short payload preview and expiry. Signed policy files with an `x5c` certificate chain are filed as low, tokens carrying a secret-like claim (`key`, `secret`, `password`...) as high
- **Private key triage**: separates mbedTLS/PolarSSL marker constants from real keys with a base64 body
- **Credentials embedded in URLs** (`user:pass@host`)
- **Valid HTTP/HTTPS hosts only**: `https://token` or `https://:%d` are discarded. Each URL appears once, with the files that contain it
- **Noise filters** for common third-party libraries, SDK internals, XML namespaces, captive-portal checks and license links
- **HTML report** (`-H`) with severity counters, an attention panel, merged duplicates, a collapsible view per rule and clickable links

## Requirements

`bash` 4+, `unzip`, `strings`, `grep`, `awk`, `sed`, `base64`. `plutil` is optional (used to read the bundle ID of an IPA).

Developed and tested on Linux with `mawk`, `gawk` and the one-true-awk. macOS ships bash 3.2, so install a newer one (`brew install bash`) and run the script with it. macOS has not been tested.

## Quick start

```bash
git clone https://github.com/jbonagura/finding_secrets.git
cd finding_secrets

bash find_secrets.sh app.apk
bash find_secrets.sh -H report.html app.ipa
```

The upload through the GitHub web UI does not keep the executable bit, so use `bash find_secrets.sh ...` or run `chmod +x find_secrets.sh` once.

## Usage

```
./find_secrets.sh [options] <file.apk | file.ipa | binary>
```

| Option | Description |
| --- | --- |
| `-o <file>` | Text report output file (default: `secrets_findings.txt`) |
| `-u <file>` | Full URL list output file (default: `urls_found.txt`) |
| `-H <file>` | Also write an HTML report |
| `-x <regex>` | Skip files whose path matches this extended regex, e.g. `-x 'VendorSDK\|Frameworks/Realm'` |
| `-a` | Disable the noise filters and scan third-party libs and SDKs too |
| `-h` | Show help |

Examples:

```bash
bash find_secrets.sh app.apk
bash find_secrets.sh -o report.txt -u urls.txt app.ipa
bash find_secrets.sh -H report.html app.apk
bash find_secrets.sh -x 'VendorSDK|Frameworks/Realm' -H report.html app.ipa
bash find_secrets.sh -a libnative.so
```

## Report sections

| # | Section | What it catches |
| --- | --- | --- |
| 0 | Hits inside the app's own package | Secret-related keywords in the app's own code (only if the package name is detected) |
| 1 | Keyword + assignment + value | `api_key = "abc12345..."`, `"client_secret": "..."`, Android `<string name="..._key">` entries |
| 2 | Known token formats | AWS, Google, Stripe, GitHub, Slack, JWT, `PRIVATE KEY` (annotated) |
| 3 | URLs with embedded credentials | `https://user:pass@host/...` |
| 4 | Unique HTTP/HTTPS hosts | One line per host with URL and file counts. Full list in `urls_found.txt` |

## Severity (HTML report)

| Severity | Examples |
| --- | --- |
| **Critical** | Private key with a real base64 body, Stripe live key, GitHub token |
| **High** | AWS access key ID, Google API key, Slack token, credentials in a URL, assignments named like `password`/`private_key`/`client_secret`, JWT carrying a secret-like claim |
| **Medium** | Other secret-like assignments, JWT, Stripe test key, inconclusive private key marker, cleartext HTTP endpoints, internal/private addresses, non-production hosts |
| **Low** | Hits in the app's own package, TLS-library key markers, signed JWS with an `x5c` chain, expired JWT |

Severity comes from the rules in `build_findings` inside the script. Adjust it there if your threat model differs. Loopback addresses (`localhost`, `127.x`) are ignored on purpose, since hybrid apps routinely serve their own assets from `https://localhost/`.

## Example output

Text report (excerpt):

```
### 1. Keyword + assignment + value (8+ chars) ###
[assets/config.json] "client_secret": "Demo-Secret-1234567",
[assets/config.json] api_key = "demo1234abcd5678"

### 2. Known token formats ###
[assets/config.json] -----BEGIN RSA PRIVATE KEY-----  <-- [WARNING: long base64 body after marker - may be a real key, extract and validate with openssl]
[assets/policies/policy_1.jws] eyJhbGciOiJSUzUxMiIs...[3387 chars]  <-- [JWT alg=RS512, x5c certificate chain: signed JWS (policy/config), not a credential]

### 4. Unique HTTP/HTTPS hosts (full URLs and files in urls_found.txt) ###
https://api.example.com  (2 URLs, 2 files)
http://staging.example.com  (1 URL, 2 files)
```

URL list (grouped by host, each URL once):

```
=== https://api.example.com ===
https://api.example.com/v1/login?client=android&lang=en
    - assets/config.json
    - res/xml/endpoints.txt
```

A full interactive report built from a fictional app is in [`sample_report.html`](sample_report.html). Download it and open it in a browser, or [preview it online](https://htmlpreview.github.io/?https://github.com/jbonagura/finding_secrets/blob/main/sample_report.html).

## Tuning the noise

The filters are plain variables near the top of the script, so tuning does not require touching the logic:

| Variable | Purpose |
| --- | --- |
| `EXCLUDE_LIBS_REGEX` | Well-known native libs and frameworks skipped by default |
| `NOISE_REGEX` | Third-party SDK package names filtered out of keyword/token hits |
| `URL_NOISE` | XML namespaces, license and schema URLs hidden from the URL list |
| `BENIGN_HTTP_HOSTS` | Cleartext hosts that do not raise an alert (captive-portal checks, library project pages) |
| `SECRET_NAMES` | Keyword list used by the assignment rule |

For one-off cases, `-x` is faster than editing the script.

## Using it in CI

A crude gate that fails the build when anything is found:

```bash
bash find_secrets.sh -o report.txt -u urls.txt app-release.apk
! grep -q '^\[' report.txt || { echo "Hardcoded secrets found"; exit 1; }
```

The script exits 0 even when it finds something, so the gate reads the report. Start there and tune it, for example by checking only sections 1 to 3, since low-severity constants also count in the example above.

## Limitations

- **String-level only.** It does not decompile, follow data flow or run the app. A key assembled at runtime from fragments will walk past it.
- **Letters-only values are skipped** by the assignment rule, because they are almost always identifiers or log text. A long all-letters passphrase can slip through.
- **In `.dex` files, string constants are usually separate strings**, so the assignment rule hits more often in JSON, XML, plist and JS. Real secrets in bytecode depend on the known token formats.
- **Severity is a heuristic.** A JWT with a `key` claim may be a public SDK identifier, and a "private key marker" may be a library constant. Always validate the finding.
- Tools like [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) cover far more (manifest review, crypto, dynamic analysis). This script is a quick first pass that runs locally with no server and no upload, and it complements them.

## Handling the reports

Reports contain the matched strings, which means they can contain **real secrets** if the scan finds any. Treat them as sensitive and never commit a report from a real app. This repository ignores them by default (see [`.gitignore`](.gitignore)):

```
secrets_findings.txt
urls_found.txt
report*.txt
*.html
!sample_report.html
*.apk
*.ipa
```

## Disclaimer

This tool is provided for authorized security testing, research and education. You are responsible for complying with the law and with the terms of your engagement. The authors accept no liability for misuse.

## License

Released under the MIT License. See [LICENSE](LICENSE).

## Author

Jordan Bonagura, [Secure Ideas - Professionally Evil](https://www.secureideas.com)
