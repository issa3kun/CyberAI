# CyberAI API Backend

This Flask backend checks public HTTP, HTTPS, FTP, and SFTP URLs.

## Run locally

Extract the ZIP and open the `cyberai-api-backend` folder in VS Code. In the PowerShell terminal, run:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Leave Flask running and use a second terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:5000/api/health
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/api/scan -ContentType 'application/json' -Body '{"url":"https://example.com"}'
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:5000/api/domain-check -ContentType 'application/json' -Body '{"target":"example.com"}'
```

## API

| Route | Input | What to read |
| --- | --- | --- |
| `GET /api/health` | None | `status` confirms Flask is running. |
| `POST /api/scan` | `{"url":"https://example.com"}` | `checks.live_response` contains HTTP evidence in the original JSON format. `checks.service_response` contains FTP or SSH evidence. |
| `POST /api/domain-check` | `{"target":"example.com"}` | `status` is `public_address`, `no_address`, `lookup_failed`, or `blocked`. Accepts a hostname, IP, or a URL using one of the four supported schemes. |

**HTTP and HTTPS compatibility.** The default `POST /api/scan` uses the original JSON format. `success: true` and `status: "URL validated"` indicate that validation passed. Read `checks.live_response.request_completed` and `checks.live_response.http_status_code` for the target response. Cookies appear in `checks.live_response.cookies` with their names and security attributes. Cookie values are omitted.

**Detailed scan results.** Use `POST /api/scan?details=1` with the same JSON body for HTTP or HTTPS to include `checks.domain`, `website_responded`, `page_accessible`, and `resource_status`. In this format, `success` indicates a target response. For example, a target HTTP 404 gives `website_responded: true`, `page_accessible: false`, and `resource_status: "http_not_found"`. FTP and SFTP use the detailed format by default. A blocked target or invalid scan input returns HTTP 400.

**Checking a hostname.** A public address confirms that the resolver found an address, or that the supplied address was public. DNS lookup alone cannot verify domain registration, a running service, or a specific path.

**Checking FTP or SFTP.** Submit `ftp://your-authorized-host` or `sftp://your-authorized-host`. FTP reads a bounded greeting without sending commands. `ftp_ready` is true for code 220 and false for codes 120 or 421. SFTP checks the underlying SSH handshake. Host-key trust, SFTP subsystem access, and file or directory paths remain unverified. Neither check authenticates or transfers files.

The scanner connects to validated public addresses on standard ports only (80, 443, 21, and 22). HTTP redirects are reported without following them. Keep the development API local.
