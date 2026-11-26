# mini-soc

[![CI](https://github.com/KimThanhTran/mini-soc/actions/workflows/ci.yml/badge.svg)](https://github.com/KimThanhTran/mini-soc/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)

A small security operations centre you can run with one command. Logs from SSH, web servers and Windows go in; Sigma-style
rules, two honeypots and an anomaly model raise alerts; alerts group into incidents that an analyst works through a status
life cycle with a response checklist. Everything runs inside a Docker network that has no route to the internet.

![Overview: live alert feed, alerts per five minutes, top attackers](docs/overview.png)

It exists to show the three parts of SOC work, and how they feed each other:

| SOC duty | Where it lives here |
|---|---|
| **Operate security systems** | Ingestion API with signed sensors, a rule engine with versioned Sigma-style rules, two honeypot sensors, hardened containers, CI that boots the whole stack |
| **Monitor, analyse and handle incidents** | Alerts mapped to MITRE ATT&CK, incidents with a status life cycle, timeline, analyst notes and a response playbook per incident type, dashboard with live feed and coverage matrix |
| **Join larger technology projects** | Four services plus a database wired with Compose, a documented threat model, an honest evaluation of the ML part, tests for every rule |

Vietnamese summary: [see the end of this page](#tóm-tắt-tiếng-việt).

## Run it

You need Docker (Compose v2). Nothing else.

```powershell
docker compose up --build
```

Open <http://127.0.0.1:8080> and sign in with the demo token `demo-analyst-token-change-me`. The `simulator` container runs
once after the API is healthy: it replays an hour of benign traffic, sends ten labelled attack scenarios, then attacks the two
honeypots over the Compose network. About a minute later the dashboard is full. To replay it, or to play it again with
another seed:

```powershell
docker compose run --rm simulator python simulate.py --seed 7
```

To use your own secrets, copy `.env.example` to `.env` and fill it in. Without one, Compose uses the labelled demo values and
the API logs a warning. The dashboard is the only published port, and only on `127.0.0.1`; the API's Swagger page is at
<http://127.0.0.1:8080/api/docs>.

Run the tests without Docker:

```powershell
python -m venv backend/.venv
backend/.venv/Scripts/pip install -r backend/requirements-dev.txt -r sensors/requirements.txt
cd backend; ../backend/.venv/Scripts/python -m pytest --cov=app    # 104 tests, 92 % line coverage
cd ..; backend/.venv/Scripts/python -m pytest sensors/tests         # 16 tests (honeypots, shipper, simulator guard)
cd frontend; npm ci; npm test; npm run build                        # 4 tests
```

## Architecture

```mermaid
flowchart LR
  subgraph lab["Docker network 'lab' (internal: no route to the internet)"]
    SIM["simulator<br/>benign + labelled attacks"]
    SSH["ssh-honeypot<br/>asyncssh, rejects every login"]
    WEB["web-honeypot<br/>FastAPI decoy admin site"]
    subgraph API["api (FastAPI, one worker)"]
      ING["/api/ingest<br/>HMAC + replay check + rate limit"] --> NORM["normalise<br/>sshd, access log, Windows, honeypot"]
      NORM --> ENG["rule engine<br/>Sigma-style YAML, sliding windows"]
      NORM --> ML["IsolationForest<br/>per-source features"]
      ENG --> INC["alerts → incidents<br/>life cycle, timeline, playbooks"]
      ML --> INC
    end
    DB[("PostgreSQL")]
    SIM -- "logs, signed" --> ING
    SIM -. "real SSH and HTTP attempts" .-> SSH
    SIM -. " " .-> WEB
    SSH -- "credentials tried, signed" --> ING
    WEB -- "requests, signed" --> ING
    NORM --> DB
    INC --> DB
  end
  UI["dashboard (React + nginx)<br/>127.0.0.1:8080"] -- "bearer token" --> API
  ANALYST(("analyst")) --> UI
```

The pieces, and why they are shaped this way:

- **One normalised event.** sshd lines, combined-format access logs, Windows event records (4624, 4625, 4732) and honeypot
  records all become `{ts, source, src_ip, user, action, outcome, http_*, geo, extra}`. Rules are written against that
  shape, so a brute-force rule covers SSH, Windows and the honeypots without caring where the failures came from.
  Records that cannot be understood are reported back to the sensor, never stored as guesses.
- **The engine is in memory and event-timed.** Windows slide on the events' own timestamps, so a replay or a test gives the
  same answer every time. The price is that its state lives in one process: run one worker (the Dockerfile does).
- **Alerts group into incidents by attacker.** One open incident per source address (or account when there is none); alerts
  from the same entity within 30 minutes join it, and each new incident type adds its playbook steps.
- **The honeypots are decoys on the same bus.** A contact is an event like any other, so a honeypot hit and a brute-force burst
  from the same address land in one incident.

## Detection rules

Rules are YAML files in [`backend/app/rules/`](backend/app/rules). A test fails if a rule has no ATT&CK technique and tactic,
or if it has no positive and negative test.

| Rule | ATT&CK | Level | Fires when |
|---|---|---|---|
| `ssh-brute-force` | T1110.001 Password Guessing | high | 10+ failed logins from one address within 60 s (SSH, Windows, honeypots) |
| `password-spraying` | T1110.003 Password Spraying | high | 8+ distinct usernames failed from one address within 5 min |
| `impossible-travel` | T1078 Valid Accounts | high | one account logs in from two countries >500 km apart faster than 900 km/h |
| `web-scanning` | T1595.002 Vulnerability Scanning | medium | 15+ distinct paths answered 404 for one address within 60 s |
| `web-sqli-probe` | T1190 Exploit Public-Facing Application | high | request path carries `UNION SELECT`, `OR 1=1`, `SLEEP()`, `information_schema` |
| `web-path-traversal` | T1190 Exploit Public-Facing Application | high | request path climbs out of the web root or names `/etc/passwd`; decoded twice, so `%252e%252e` does not hide it |
| `priv-esc-after-login` | T1548.003 Sudo, T1098 Account Manipulation | high | same account spawns a root shell or is added to Administrators within 10 min of a login |
| `honeypot-ssh-contact` | T1133 External Remote Services | medium | any login attempt on the decoy SSH server |
| `honeypot-web-contact` | T1595 Active Scanning | medium | any request to the decoy admin site |

A rule looks like this (the real file also carries a description and the incident type):

```yaml
id: password-spraying
level: high
tags: [attack.credential_access, attack.t1110.003]     # tactic and technique
detection:
  failed_login: {action: auth, outcome: failure}
  condition: failed_login                              # and / or / not / parentheses over selection names
correlation:
  type: value_count        # event_count | value_count | temporal | impossible_travel
  value_field: user
  group_by: [src_ip]
  timespan: 5m
  threshold: 8
```

Selections support `contains`, `startswith`, `endswith`, `re`, `gte`/`gt`/`lte`/`lt`; lists are OR, fields are AND, strings
compare case-insensitively. After an alert the same rule stays quiet for the same key for one timespan (or `cooldown`), so one
burst is one alert.

## Incident handling

![An incident: playbook checklist, analyst notes, timeline and the alerts behind it](docs/incident.png)

```mermaid
stateDiagram-v2
  [*] --> new
  new --> investigating
  new --> closed
  investigating --> contained
  investigating --> closed
  contained --> investigating: reopen, or automatically on new activity
  contained --> closed
  closed --> investigating: reopen
```

Every change is written to the incident's timeline (alerts, status moves, playbook ticks, note edits). The server refuses
illegal moves with `409`. Playbooks exist for brute force, spraying, impossible travel, web attacks, privilege escalation,
honeypot contact and anomalies (for example "block the source address", "reset the password of every account that
succeeded", "isolate the host").

The ATT&CK view shades each technique by how many alerts its rules raised:

![ATT&CK coverage matrix](docs/coverage.png)

## Honeypots

Both are small Python services on the internal network, shipping every touch through the same signed API as any other sensor.

- **`ssh-honeypot`** speaks real SSH ([asyncssh](https://asyncssh.readthedocs.io)), presents an OpenSSH banner, asks for a
  password for every username, **always says no**, and reports the username and password tried. It never opens a session.
- **`web-honeypot`** is a FastAPI decoy "router admin" site. A few bait paths (`/admin`, `/wp-login.php`, `/phpmyadmin/`)
  return a login form, everything else 404s. Posted credentials are captured and refused. Pages are static text, so nothing
  the visitor sends is ever reflected.
- Containers run as non-root with a read-only file system, no capabilities, memory and process limits, and no route out.
  They are not published on the host. See [SECURITY.md](SECURITY.md).

## Anomaly detection (IsolationForest)

For every source address the model sees the last five minutes and four numbers: **failed logins per minute**,
**distinct usernames tried**, **requests per minute**, **share of HTTP errors**. It is an
[IsolationForest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html) trained at API
start on six hours of generated benign traffic only (no attacks), and it scores each source that sent events, once per tick.
A window with fewer than five events is not scored. Alerts say which numbers drove them and carry no ATT&CK id, because a
statistical outlier is not a technique.

**How well does it work?** `python -m app.evaluate` generates a test set the model never saw and compares the detectors.
Unit of evaluation: a source address. An attacker is detected if any alert names it; a benign source is a false positive if
any alert names it. Ten seeds, each with 120 min of benign traffic and 8 instances of each of 10 scenarios (7 classic, 3 slow).
Full output in [docs/ml-evaluation.md](docs/ml-evaluation.md).

| Detector | Precision | Recall | False-positive benign sources per run |
|---|---|---|---|
| rules only | 1.00 | 0.67 | 0.0 |
| model only | 0.96 | 0.69 | 2.3 |
| rules + model | 0.97 | 0.97 | 2.3 |

| Scenario | Kind | Rules | Model | Both |
|---|---|---|---|---|
| ssh_bruteforce, password_spray, web_scan | classic | 1.00 | 1.00 | 1.00 |
| sqli_probe | classic | 1.00 | 0.88 | 1.00 |
| path_traversal | classic | 1.00 | 0.00 | 1.00 |
| priv_esc | classic | 0.97 | 0.00 | 0.97 |
| impossible_travel | classic | 0.71 | 0.00 | 0.71 |
| **slow_bruteforce** (4 failures/min) | slow | **0.00** | **1.00** | 1.00 |
| **slow_spray** (1 username/min) | slow | **0.00** | **1.00** | 1.00 |
| **slow_scan** (10 paths/min) | slow | **0.00** | **1.00** | 1.00 |

How to read this, honestly:

- **The slow attacks were built to sit under the rule thresholds**, so "the model catches what the rules miss" is true by
  construction. It shows that the two detectors are complementary, not that the model would find real attackers.
- **The data is synthetic and so is the baseline**, both written by me from the same generator. Real traffic is messier, so
  expect worse precision. Treat the numbers as a regression check, not a benchmark.
- The model never fires on `path_traversal`, `priv_esc` or `impossible_travel`: those are single events or two events, not a
  rate, so the four features cannot see them. That is why the rules exist.
- The 0.71 for `impossible_travel` is a test-set artefact: every one of the 23 misses (out of 80) has another instance on
  the same victim account within 40 minutes, and the rule tracks one last login per account and then cools down for 30 minutes.
- Over the ten runs the 23 false positives were the misconfigured service account (10), the link checker with its broken links
  (6) and ordinary users who mistyped a password several times (7). The threshold (`contamination=0.02`) is a
  precision/recall dial: at 0.005 the model had no false positives and caught only 20 % of the attackers.

## Threat model

What this platform protects and from whom. Assets: the integrity of alerts and incidents (a forged or suppressed alert is
worse than none), the analyst token, the sensors' signing keys, and the captured credentials.

| Threat (STRIDE) | Where | Mitigation | Residual |
|---|---|---|---|
| **Spoofing** a sensor, to inject or flood events | `/api/ingest` | HMAC per sensor, 5-minute skew limit, replay cache, one generic `401` | Keys are shared secrets with no rotation; a stolen key is a stolen sensor |
| **Tampering** with a request in transit | sensor → API | Signature covers timestamp and body | No TLS inside the lab network; put a proxy with TLS in front of anything real |
| **Tampering** with an incident | analyst API | Token required; server-enforced life cycle; every change in the timeline | One shared token: no per-analyst attribution |
| **Repudiation** by an analyst | timeline | Status moves, notes and playbook ticks are recorded | Entries do not name a person (single token) |
| **Information disclosure** of captured credentials | database | Passwords truncated to 64 characters; internal network; nothing published but the dashboard | Not encrypted at rest; never purged |
| **Denial of service** by a log flood | `/api/ingest` | Rate limit, 1 MB and 500-event caps, bounded in-memory windows | The rate limiter is per client address in one process |
| **DoS / evasion** by an attacker who knows the rules | engine | Slow-attack model; double URL decoding | A patient attacker under every threshold is still invisible to the rules |
| **Elevation of privilege** via a honeypot | sensors | No session, no command, static pages, non-root, read-only, no capabilities, no route out | A bug in asyncssh or FastAPI would be a bug in a sandboxed container |
| **Poisoning** the anomaly baseline | model | Trained once at start on generated data, not on live traffic | Training on live traffic later would open this up |
| Poisoned log content (`%00`, huge numbers, injection strings) | normaliser | Parsed with fixed regexes, length caps, NUL escaped (PostgreSQL rejects it), parameterised SQL | – |

## Hardening in the repository

Signed ingestion, rate limiting, input validation, no secrets committed (the app refuses secrets shorter than 16
characters), exact version pins for every Python package plus `package-lock.json`, non-root read-only containers with all
capabilities dropped, an internal network, a strict CSP on the dashboard. Details and gaps in [SECURITY.md](SECURITY.md).

## Limitations

- **One analyst token, no users or roles.** A real SOC needs accounts, roles and audit of who did what.
- **The engine's windows live in one process's memory.** A restart forgets partial windows, and a second worker would split
  the state. Scaling out means moving the windows to Redis or a stream processor.
- **A batch the API keeps failing on is dropped** after five tries so one bad record cannot block a sensor, which also loses the
  other records in that batch. Plain outages are retried for as long as they last.
- **No duplicate protection.** Re-sending the same batch creates the same events and alerts twice (only the signature replay
  is blocked, within five minutes).
- **GeoIP is a stub.** `geo_lookup` knows the simulator's synthetic `10.<region>.x.x` ranges. A real deployment plugs in a
  GeoIP database, and then needs allow-lists for VPNs and travel to keep impossible-travel usable.
- **No migrations, no retention.** Tables are created at start; nothing is archived or deleted.
- **The dashboard polls every few seconds** instead of using WebSockets or server-sent events.
- **The evaluation is on synthetic data** (see above). Nothing here was tested against real attackers or real logs.
- **Response is a checklist, not automation.** "Block the IP" is a step for a human; nothing touches a firewall.
- **Not tested with the SSH honeypot exposed to the internet**, and deliberately not designed for it.

## Layout

```
backend/    FastAPI app: normalise.py, rules.py + rules/*.yml, engine.py, incidents.py, ml.py, pipeline.py, main.py,
            simulation.py (traffic generator), evaluate.py (precision/recall); tests/
sensors/    ssh_honeypot.py, web_honeypot.py, ship.py (signed shipper); tests/
simulator/  simulate.py: backfills history, sends labelled attacks, attacks the honeypots (private addresses only)
frontend/   Vite + React dashboard: overview, incident board, ATT&CK matrix; light/dark, EN/VI
docs/       screenshots, ml-evaluation.md
```

## Tóm tắt tiếng Việt

**mini-soc** là một trung tâm giám sát an toàn thông tin thu nhỏ, chạy bằng một lệnh `docker compose up --build`. Nhật ký SSH,
web và Windows được chuẩn hoá về một dạng sự kiện chung, rồi đi qua **bộ rule viết theo kiểu Sigma** (mỗi rule gắn mã kỹ thuật
MITRE ATT&CK), hai **honeypot** (SSH giả và trang quản trị web giả) và một mô hình **IsolationForest** phát hiện hành vi bất thường.
Cảnh báo được gom thành **sự cố** theo nguồn tấn công, có vòng đời *mới → đang điều tra → đã khoanh vùng → đã đóng*, dòng thời gian,
ghi chú của analyst và playbook ứng phó theo loại sự cố. Bảng điều khiển React có cảnh báo trực tiếp, bảng sự cố, ma trận độ phủ
ATT&CK, danh sách nguồn tấn công hàng đầu, giao diện sáng/tối và Anh/Việt.

- **Vận hành hệ thống bảo mật:** API nhận log có ký HMAC, chống replay, giới hạn tốc độ; container chạy không quyền root, hệ tệp chỉ đọc,
  mạng nội bộ không ra được Internet; CI dựng cả hệ thống thật.
- **Giám sát, phân tích, xử lý sự cố:** 9 rule × ATT&CK, vòng đời sự cố do server kiểm soát, playbook cho từng loại.
- **Dự án công nghệ lớn:** 4 dịch vụ + PostgreSQL ghép bằng Compose, 104 test backend (mỗi rule có test dương và âm), mô hình đe doạ.
- **Trung thực về mô hình ML:** trên dữ liệu mô phỏng, rule đạt recall 0,67; thêm mô hình lên 0,97 (precision 0,97). Các kịch bản
  "tấn công chậm" được thiết kế để nằm dưới ngưỡng rule nên kết quả này chỉ chứng minh hai bộ phát hiện **bổ sung** cho nhau,
  không phải độ chính xác trên dữ liệu thật. Xem mục *Limitations*.

Chạy thử: `docker compose up --build`, mở <http://127.0.0.1:8080>, token demo `demo-analyst-token-change-me` (chỉ dùng trên máy cá nhân).
