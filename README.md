# AI Agent DFIR Framework v1

A complete, offline forensic framework for collecting and analyzing artifacts
from AI coding agents and assistants.

## Capabilities

### Collection
- Retains the proven Windows/Falcon RTR Codex/Gemini collector.
- Includes a cross-platform Python collector for Windows, macOS, and Linux.
- Includes a native macOS Bash collector for endpoints without Python.
- Collects likely artifacts for Codex, Claude Code, Gemini CLI, Cursor,
  Windsurf, Continue, and Aider.
- Hashes acquired files and creates a collection manifest.

### Parsing and normalization
- Codex session JSONL and normalized Codex collector timelines.
- Codex runtime SQLite databases.
- Best-effort JSON/JSONL adapters for Claude Code, Gemini CLI, Cursor,
  Windsurf, Continue, Aider, and Copilot-related exports.
- Adapter diagnostics explicitly identify parsed, unsupported, and failed files.

### Artifact enrichment
- Commands and shell activity.
- Git operations.
- File reads, writes, and patches.
- Working directories and referenced paths.
- MCP, plugin, skill, approval, model, token, and network activity.
- Potential secret exposure with masked values.

### Correlation
- Merges AI-agent evidence into a single UTC timeline.
- Imports EDR, SIEM, Plaso, or other telemetry from CSV.
- Correlates by timestamp, session, turn, call, process, user, and host fields.
- Suppresses near-duplicate runtime/session records while retaining source links.

### IOC and governance outputs
- URLs, domains, IPv4 addresses, file hashes, AWS ARNs, Azure resource IDs,
  GCP project IDs, registry paths, and file paths.
- CSV indicator export.
- STIX 2.1 indicator bundle for supported observable types.
- Agent, model, tool, path, Git, token, and potential-secret analytics.

### Case replay
The standalone HTML report includes an investigator-friendly Case Replay tab
that shows only user prompts and agent replies in chronological order. Duplicate
copies from multiple artifacts are collapsed to one representative record, and
user and agent messages are color coded for fast review.

## Package contents

- `aia_dfir.py` — main cross-platform collector and analyzer.
- `Invoke-AIAgentForensics.ps1` — Falcon RTR-compatible Windows Codex collector.
- `Collect-AIAgentForensics-macOS.sh` — native macOS collector requiring no Python.

Python 3.9 or newer is recommended. No third-party packages are required.

## Falcon RTR workflow

On the endpoint:

```
powershell .\Invoke-AIAgentForensics.ps1 -IncludeRawArtifacts
```

Retrieve the ZIP printed as `RETRIEVE_FILE`.

On the analyst workstation:

```
python .\aia_dfir.py analyze C:\Cases\CodexDFIR_HOST_TIMESTAMP.zip -o C:\Cases\AI_Agent_Investigation
```

## Cross-platform collection

```
python3 aia_dfir.py collect -o ./AI_Agent_Artifacts
```

Then analyze the collection ZIP:

```
python3 aia_dfir.py analyze ./AI_Agent_Artifacts.zip -o ./Investigation
```

## macOS collection without Python

The native macOS collector uses the Bash version and system utilities included
with macOS. It collects raw Codex session/runtime evidence and Gemini
Antigravity transcripts, creates a CSV inventory and SHA-256 manifest, and
packages everything for offline analysis. It does not parse evidence on the
endpoint.

Collect the current user's artifacts:

```bash
chmod +x ./Collect-AIAgentForensics-macOS.sh
./Collect-AIAgentForensics-macOS.sh
```

Collect all eligible profiles under `/Users`:

```bash
sudo ./Collect-AIAgentForensics-macOS.sh --all-users
```

Choose a specific profile or output location:

```bash
sudo ./Collect-AIAgentForensics-macOS.sh \
  --user-home /Users/alice \
  --output-root /private/var/tmp
```

The collector prints `RETRIEVE_FILE=/path/to/archive.zip` when successful.
Transfer that ZIP to an analyst workstation and run:

```bash
python3 aia_dfir.py analyze \
  ./AIAgentDFIR_macname_timestamp.zip \
  -o ./Investigation
```

Raw artifacts are always included because the Bash collector deliberately
leaves JSONL and SQLite parsing to the offline analyzer. Use `--no-zip` only
when directory output is required. For all-user collection, grant Full Disk
Access to the terminal or remote-management process running the script; macOS
privacy controls can restrict data access even when the process runs as root.

## Correlating EDR or SIEM data

```
python .\aia_dfir.py analyze C:\Cases\CodexDFIR.zip --external-csv C:\Cases\falcon_events.csv --external-csv C:\Cases\plaso_timeline.csv -o C:\Cases\Correlated_Report
```

The importer recognizes common timestamp fields such as `TimestampUtc`,
`timestamp`, `time`, `datetime`, and `@timestamp`, plus common message,
hostname, username, process, and category columns.

## Investigation output

- `AI_Agent_DFIR_Report.html`
- `AI_Agent_Timeline.csv`
- `AI_Agent_Timeline.jsonl`
- `Case_Replay.csv`
- `Indicators.csv`
- `Indicators_STIX_2.1.json`
- `Analytics.json`
- `Ingestion_Diagnostics.csv`
- `SHA256SUMS.txt`

## Limitations

AI-agent artifact formats are not stable public forensic schemas. Codex parsing
is the most thoroughly developed adapter in this package. Other agent adapters
are deliberately labeled best-effort and should be validated against known
test data from the relevant version.

STIX indicators are exported as unvalidated investigative leads. Potential
secret detection masks displayed values but the original evidence remains in
the collected artifacts and timeline.