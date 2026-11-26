# Security policy

mini-soc is a portfolio project, not a product. It is built to be read, run on a laptop and criticised. If you find a
weakness, I would like to hear about it.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository (Security tab, "Report a vulnerability"), or open an issue if the
finding is not sensitive. Please include what you did, what you expected and what happened. I aim to answer within a week.

## What the platform defends

| Surface | Control |
|---|---|
| `POST /api/ingest` | Per-sensor HMAC-SHA256 over `timestamp + "." + body`; clock skew limited to 5 minutes; every signature is accepted once (replay cache); one generic `401` for every failure so it leaks nothing about which part was wrong |
| Analyst API | Bearer token compared in constant time; same rate limiter as ingestion, so guessing is throttled |
| Input | Pydantic validation on every body; source whitelist; field length caps; IP addresses parsed with `ipaddress`; at most 500 events and 1 MB per request; unreadable records are reported, never stored as guesses; timestamps limited to 7 days back and 5 minutes ahead |
| Abuse | Token-bucket rate limits on ingestion and on the analyst API (`429`) |
| Secrets | None in the repository. The app refuses to start with secrets shorter than 16 characters and logs a warning if they contain `demo`. `.env` is git-ignored; `.env.example` lists what to set |
| Dependencies | Every Python package is pinned to an exact version (`requirements*.txt`, transitive packages included); the front end is pinned by `package-lock.json`; base images are pinned to a minor tag |
| Containers | Non-root users, read-only root file systems, all capabilities dropped, `no-new-privileges`, memory and process limits on the honeypots |
| Network | The `lab` Docker network is `internal`: no container can reach the internet and nothing on it is published. Only the dashboard is published, and only on `127.0.0.1` |
| Front end | Strict `Content-Security-Policy`, `X-Frame-Options: DENY`, `nosniff`; the token lives in `sessionStorage` and is sent only as a header |

## Honeypot safety

- The decoy SSH server grants no session and runs no command: `validate_password` always returns `False`.
- The decoy web site serves static pages and never echoes anything the visitor sent, so it cannot be turned into an XSS or injection vector.
- Both honeypots sit on the internal network. A compromised honeypot has no route out and no credentials except its own
  ingestion key.
- Captured passwords are truncated to 64 characters. They are attacker guesses, but a legitimate user can mistype a real
  password into a decoy, so treat the database as sensitive.
- The simulator refuses to send traffic to any address that is not private or loopback.
- `TRUST_XFF=1` on the web honeypot (set by `docker-compose.yml`) lets the simulator pretend to be several addresses. The
  header is spoofable; turn it off anywhere real traffic could reach the sensor.

## Known gaps (not defended)

See the Limitations section of the [README](README.md). The ones that matter for security: one shared analyst token
instead of per-user accounts with roles, no TLS (put a reverse proxy in front of anything beyond localhost), sensor
secrets are shared symmetric keys with no rotation, the database is not encrypted at rest, and logs of captured
credentials are never purged.

## Using it responsibly

Run it only on systems you own. The simulator and honeypots are for demonstration inside the compose network; do not point
the simulator at anything else, and do not expose the honeypots to the internet without understanding the consequences.
