# PhantomForge

PhantomForge is a local, offline, desktop-style pentest workflow GUI for orchestrating nmap, tshark/Wireshark, sqlmap, BeEF, and John the Ripper. It defaults to guarded mock mode so the whole workflow can be validated before touching a real authorized target.

```
React/Vite SPA
     |
FastAPI REST + /ws event stream
     |
Pipeline state machine
     |
SQLite  <->  Tool runners  <->  reports/
              nmap tshark sqlmap beef john
```

## Safety Model

- No tool runs before Start is pressed.
- Each run requires an `Authorized target scope`; targets outside that CIDR/domain string are rejected.
- Gates default on in `config.yaml`.
- `allow_destructive: false` strips sqlmap shell options and appends safer flags.
- Commands, output, parse errors, and exit codes are logged to each run directory.
- No cloud calls or telemetry are used.

Use this only against systems you are authorized to test.

## Setup

```bash
cd phantomforge
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd frontend
npm install
npm run build
cd ..
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000`.

On Kali, install external tools:

```bash
bash scripts/install_kali_deps.sh
```

## Mock Mode Walkthrough

Mock mode is enabled by default in `config.yaml`:

```yaml
mock: true
```

You can also force it:

```bash
MOCK_TOOLS=1 uvicorn backend.main:app
```

In the GUI:

1. Keep target `192.0.2.10`.
2. Keep scope `192.0.2.0/24`.
3. Press Start.
4. Watch per-phase logs in Live Console.
5. Review findings and cracked passwords.
6. Open the generated HTML report from Reports.

The mock run emits:

- nmap XML with two hosts and web services.
- tshark analysis with a fake HTTP credential and NetNTLMv2 hash.
- sqlmap JSON with one demo injection and md5crypt hash.
- BeEF with one fake hooked browser.
- John output with deterministic cracked values.

## Real Usage Example

Edit `config.yaml`:

```yaml
mock: false
allow_destructive: false
tools:
  nmap: /usr/bin/nmap
  tshark: /usr/bin/tshark
  sqlmap: /usr/bin/sqlmap
  john: /usr/bin/john
```

Start the server, enter a target such as `10.10.10.25`, and set scope to an authorized CIDR such as `10.10.10.0/24`. Live packet capture may need root privileges or proper dumpcap capabilities.

## API

- `POST /api/runs` starts a run.
- `POST /api/runs/{id}/stop` stops it.
- `GET /api/runs` lists runs.
- `GET /api/findings` returns structured findings.
- `GET /api/cracked` returns cracked hashes.
- `GET /api/reports/{id}/html` opens the self-contained HTML report.
- `GET /ws` streams `{run_id, phase, line}` events.

## Tests

```bash
MOCK_TOOLS=1 pytest
```

The suite covers config loading, nmap XML parsing, sqlmap JSON and console parsing, John output parsing, scope checks, and a full mock pipeline run.
