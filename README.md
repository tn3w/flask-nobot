<div align="center">

# flask-NoBot

Lightweight, zero-dependency bot protection for Flask. Invisible JS challenge (no CAPTCHA), regex/CIDR rule engine, HMAC-signed verification tokens.

[![PyPI](https://img.shields.io/pypi/v/flask-nobot?style=flat-square)](https://pypi.org/project/flask-nobot/)
[![Python](https://img.shields.io/pypi/pyversions/flask-nobot?style=flat-square)](https://pypi.org/project/flask-nobot/)
[![License](https://img.shields.io/github/license/tn3w/flask-nobot?style=flat-square)](https://github.com/tn3w/flask-nobot/blob/main/LICENSE)
[![Issues](https://img.shields.io/github/issues/tn3w/flask-nobot?style=flat-square)](https://github.com/tn3w/flask-nobot/issues)
[![Stars](https://img.shields.io/github/stars/tn3w/flask-nobot?style=flat-square)](https://github.com/tn3w/flask-nobot/stargazers)
[![Downloads](https://img.shields.io/pypi/dm/flask-nobot?style=flat-square)](https://pypi.org/project/flask-nobot/)

</div>

## Install

```bash
pip install flask-nobot
```

## Quick start

```python
from flask import Flask
from flask_nobot import NoBot

app = Flask(__name__)
nobot = NoBot(app, secret="change-me")
```

### App factory

```python
nobot = NoBot()

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-me"
    nobot.init_app(app)
    return app
```

Secret resolution: constructor arg → `NOBOT_SECRET` → `SECRET_KEY`.

## Config (`app.config`)

| Key                    | Default | Meaning                                                     |
| ---------------------- | ------- | ----------------------------------------------------------- |
| `NOBOT_SECRET`         | —       | HMAC key (falls back to `SECRET_KEY`)                       |
| `NOBOT_MODE`           | `auto`  | `auto` (rules only), `all` (challenge everything), `off`    |
| `NOBOT_THRESHOLD`      | `10`    | Weight total → challenge                                    |
| `NOBOT_TOKEN_TTL`      | `3600`  | Verification cookie lifetime (s)                            |
| `NOBOT_NONCE_TTL`      | `90`    | Challenge-page nonce lifetime (s)                           |
| `NOBOT_TRUST_PROXY`    | `False` | Honor `X-Forwarded-For`                                     |
| `NOBOT_DENY_BOGONS`    | `False` | Deny bogon/private source IPs (enable behind trusted proxy) |
| `NOBOT_CRAWLER_WEIGHT` | `4`     | Score added when UA looks like a crawler                    |
| `NOBOT_RULES`          | `[]`    | Extra `Rule` objects                                        |

Change prefix via `NoBot(prefix="SEC_")`.

## Route decorators

```python
from flask_nobot import skip, protect, challenge, block

@app.route("/health")
@skip
def health(): ...          # never challenged

@app.route("/login")
@protect
def login(): ...           # always evaluated

@app.route("/admin")
@challenge
def admin(): ...           # always challenged

@app.route("/api")
@block
def api(): ...             # failed challenge → 403, no retry
```

| Decorator   | Effect                              |
| ----------- | ----------------------------------- |
| `skip`      | Bypass middleware                   |
| `protect`   | Force rule eval even in `auto` mode |
| `challenge` | Always issue challenge              |
| `block`     | Deny outright on failed challenge   |

## Rules

```python
from flask_nobot import Rule

rules = [
    Rule("trusted-office", action="allow",
         remote_addresses=["10.0.0.0/8", "192.168.1.0/24"]),
    Rule("known-bad", action="deny",
         user_agent=r"(curl|wget|python-requests)"),
    Rule("suspicious-ua", action="weigh", weight=6,
         user_agent=r"(bot|crawler|spider|scrap)"),
    Rule("no-accept-lang", action="weigh", weight=4,
         headers={"Accept-Language": r"^$"}),
    Rule("admin-paths", action="challenge",
         path=r"^/admin", method="GET|POST"),
]

nobot = NoBot(app, secret="...", rules=rules, threshold=8)
```

### Built-in preset

`DEFAULT_RULES` is applied when no `rules` argument is given. Pass `rules=[]` to disable, or extend it:

```python
from flask_nobot import NoBot, DEFAULT_RULES, Rule

nobot = NoBot(app, secret="...")  # uses DEFAULT_RULES
nobot = NoBot(app, secret="...", rules=DEFAULT_RULES + [Rule(...)])
```

`DEFAULT_RULES` covers: Cloudflare-Worker deny, known-bad/vuln/WP scanners, dotfile/shell/traversal probes (deny); well-known, favicon, robots, health, search engines, feed readers, monitoring, link previews, archive.org (allow); AI bots, headless browsers, aggressive scrapers, empty UA (challenge); curl/wget, missing Accept/Accept-Language, Connection:close (weigh).

### Rule fields

| Field              | Type                                     | Notes                                     |
| ------------------ | ---------------------------------------- | ----------------------------------------- |
| `name`             | str                                      | identifier                                |
| `action`           | `allow` / `deny` / `challenge` / `weigh` |                                           |
| `path`             | regex                                    | matches URL path                          |
| `method`           | regex                                    | HTTP method (fullmatch, case-insensitive) |
| `user_agent`       | regex                                    |                                           |
| `headers`          | `dict[name, regex]`                      | header must be present AND match regex    |
| `missing_headers`  | `list[name]`                             | all listed headers must be absent/empty   |
| `remote_addresses` | `list[cidr]`                             | any match                                 |
| `weight`           | int                                      | added to score on `weigh`                 |

Evaluation: first matching `allow`/`deny`/`challenge` wins → short-circuit. All matching `weigh` rules accumulate → if score ≥ `threshold` → challenge.

## Challenge

Invisible, no user input. Serves a dark HTML page that runs JS signal collection:

- `navigator.webdriver`, plugin/language counts, hardware concurrency
- Headless/automation markers: `_phantom`, `__nightmare`, `$cdc_*`, `webdriver` attr
- Native `Function.toString` integrity
- WebGL vendor/renderer (blocks SwiftShader/llvmpipe)
- Notification-permission inconsistency trick
- Chrome object presence vs UA
- Timing floor/ceiling

Posts signals → server-side scoring → HMAC token cookie → redirect to original URL.

## Verification token

`base64(payload).base64(hmac_sha256(secret, payload))` where payload binds `{timestamp, ip-hash, ua-hash, random}`. IP/UA rebinding prevents cookie theft; TTL limits replay.

## Security

- `HttpOnly`, `Secure` (when HTTPS), `SameSite=Strict` cookies
- Required `Origin` + `X-Requested-With` check on verify → CSRF defense
- CSP on challenge page (`default-src 'none'`, no third-party), `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `X-Content-Type-Options: nosniff`
- Constant-time HMAC compare
- One-time nonce: each challenge nonce's random `r` is consumed server-side on first verify → replay blocked for `nonce_ttl`
- Crawler heuristic (`is_crawler`): regex over UA for bot signals, known tools, URLs-in-UA, absence of real browser tokens → adds `crawler_weight` to score
- Bogon detection (`is_bogon`): blocks RFC1918/loopback/link-local/reserved ranges when `deny_bogons=True` (enable behind trusted proxy)

## Formatting

```bash
pip install black isort
isort . && black .
npx prtfm
```

## License

[Apache-2.0](LICENSE)
