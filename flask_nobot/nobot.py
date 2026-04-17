from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable
from urllib.parse import urlparse

from flask import Flask, Response, current_app, jsonify, make_response, request

COOKIE_TOKEN = "_nobot"
COOKIE_NONCE = "_nobot_n"
VERIFY_PATH = "/_nobot/verify"
ACTIONS = {"allow", "deny", "challenge", "weigh"}
HEADLESS_UA = ("HeadlessChrome", "PhantomJS", "Electron")

_BOT_SIGNAL = re.compile(
    r"bot\b|crawl|spider|scrape|fetch(?![\w]*api)"
    r"|scan\b|index(?:er|ing)|preview|slurp|archiv|headless"
    r"|\+https?://|@[\w.-]+\.\w{2,}\b",
    re.I,
)

_KNOWN_TOOL = re.compile(
    r"lighthouse|playwright|selenium|wget[\s/]"
    r"|nikto|sqlmap|nmap\b|pingdom|httrack"
    r"|google[\s-](?:favicon|ads|safety|extended)"
    r"|\bby\s+\S+\.(?:com|org|net)\b"
    r"|^[\w.-]+\.(?:com|net|org|io|ai)[/\s]"
    r"|;\s*\w+-agent[);]",
    re.I,
)

_URL_IN_UA = re.compile(r"(?:^|[+;]|\s-\s)https?://[^\s);,]+", re.I)

_BROWSER = re.compile(
    r"mozilla/|webkit|gecko|trident|presto|khtml"
    r"|opera[\s/]|links\s|lynx/|\((?:windows|macintosh|x11|linux)",
    re.I,
)

_BOGONS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]


def is_crawler(user_agent: str) -> bool:
    if not user_agent:
        return True

    if _BOT_SIGNAL.search(user_agent) or _KNOWN_TOOL.search(user_agent):
        return True

    if _URL_IN_UA.search(user_agent):
        return True

    return not _BROWSER.search(user_agent)


def is_bogon(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True

    return any(addr in n for n in _BOGONS)


def _mark(policy: str) -> Callable:
    def deco(fn):
        fn._nobot_policy = policy
        return fn

    return deco


skip = _mark("skip")
protect = _mark("protect")
challenge = _mark("challenge")
block = _mark("block")


@dataclass
class Rule:
    name: str
    action: str
    path: str | None = None
    method: str | None = None
    user_agent: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    missing_headers: list[str] = field(default_factory=list)
    remote_addresses: list[str] = field(default_factory=list)
    weight: int = 0

    def __post_init__(self):
        self.action = self.action.lower()
        if self.action not in ACTIONS:
            raise ValueError(f"invalid action: {self.action}")

        self._path = re.compile(self.path) if self.path else None
        self._method = re.compile(self.method, re.I) if self.method else None
        self._ua = re.compile(self.user_agent, re.I) if self.user_agent else None

        self._headers = {
            k.lower(): re.compile(v, re.I) for k, v in self.headers.items()
        }
        self._missing = [h.lower() for h in self.missing_headers]
        self._nets = [
            ipaddress.ip_network(c, strict=False) for c in self.remote_addresses
        ]

    def matches(self, path, method, ua, headers, ip) -> bool:
        if self._path and not self._path.search(path):
            return False
        if self._method and not self._method.fullmatch(method):
            return False
        if self._ua and not self._ua.search(ua):
            return False

        for name, pat in self._headers.items():
            value = headers.get(name)
            if value is None or not pat.search(value):
                return False

        for name in self._missing:
            if headers.get(name):
                return False

        if not self._nets:
            return True

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False

        return any(addr in n for n in self._nets)


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


class NoBot:
    def __init__(
        self,
        app: Flask | None = None,
        secret: str | bytes | None = None,
        rules: Iterable[Rule] | None = None,
        threshold: int = 10,
        token_ttl: int = 3600,
        nonce_ttl: int = 90,
        mode: str = "auto",
        prefix: str = "NOBOT_",
        trust_proxy: bool = False,
        deny_bogons: bool = False,
        crawler_weight: int = 4,
    ):
        self.secret = secret

        if rules is None:
            from .presets import DEFAULT_RULES

            rules = DEFAULT_RULES
        self.rules = list(rules)

        self.threshold = threshold
        self.token_ttl = token_ttl
        self.nonce_ttl = nonce_ttl
        self.mode = mode
        self.prefix = prefix
        self.trust_proxy = trust_proxy
        self.deny_bogons = deny_bogons
        self.crawler_weight = crawler_weight

        self._html = ""
        self._key = b""
        self._used: dict[str, float] = {}

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        cfg, p = app.config, self.prefix

        secret = cfg.get(f"{p}SECRET", self.secret) or cfg.get("SECRET_KEY")
        if not secret:
            raise RuntimeError(
                "NoBot needs a secret (arg, NOBOT_SECRET, or SECRET_KEY)"
            )

        self.secret = secret
        self._key = secret.encode() if isinstance(secret, str) else secret

        self.threshold = int(cfg.get(f"{p}THRESHOLD", self.threshold))
        self.token_ttl = int(cfg.get(f"{p}TOKEN_TTL", self.token_ttl))
        self.nonce_ttl = int(cfg.get(f"{p}NONCE_TTL", self.nonce_ttl))
        self.mode = cfg.get(f"{p}MODE", self.mode)
        self.trust_proxy = bool(cfg.get(f"{p}TRUST_PROXY", self.trust_proxy))
        self.deny_bogons = bool(cfg.get(f"{p}DENY_BOGONS", self.deny_bogons))
        self.crawler_weight = int(cfg.get(f"{p}CRAWLER_WEIGHT", self.crawler_weight))
        self.rules += list(cfg.get(f"{p}RULES", []))

        template = (Path(__file__).parent / "challenge.html").read_text()
        self._html = template.replace("__URL__", json.dumps(VERIFY_PATH))

        app.add_url_rule(VERIFY_PATH, "_nobot_verify", self._verify, methods=["POST"])
        app.before_request(self._before_request)
        app.extensions.setdefault("nobot", self)

    def add_rule(self, rule: Rule) -> None:
        self.rules.append(rule)

    def _pack(self, data: dict) -> str:
        payload = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
        sig = hmac.new(self._key, payload, hashlib.sha256).digest()
        return f"{_b64e(payload)}.{_b64e(sig)}"

    def _unpack(self, token: str) -> dict | None:
        if not token or "." not in token:
            return None

        try:
            p_b64, s_b64 = token.split(".", 1)
            payload, sig = _b64d(p_b64), _b64d(s_b64)
        except Exception:
            return None

        expected = hmac.new(self._key, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None

        try:
            return json.loads(payload)
        except Exception:
            return None

    def _ctx(self) -> tuple[str, str]:
        if self.trust_proxy:
            fwd = request.headers.get("X-Forwarded-For", "")
            ip = fwd.split(",")[0].strip() if fwd else request.remote_addr
        else:
            ip = request.remote_addr

        return ip or "0.0.0.0", request.headers.get("User-Agent", "")

    def _policy(self) -> str | None:
        view = current_app.view_functions.get(request.endpoint or "")
        return getattr(view, "_nobot_policy", None)

    def _bound(self, data: dict, ip: str, ua: str, ttl: int) -> bool:
        if time.time() - data.get("t", 0) > ttl:
            return False

        return data.get("i") == _hash(ip) and data.get("u") == _hash(ua)

    def _consume(self, nonce_id: str, now: float) -> bool:
        used = self._used

        for k in [k for k, e in used.items() if e <= now]:
            used.pop(k, None)

        if nonce_id in used:
            return False

        used[nonce_id] = now + self.nonce_ttl
        return True

    def _before_request(self):
        if request.path == VERIFY_PATH:
            return None

        policy = self._policy()
        if policy == "skip":
            return None
        if self.mode == "off" and policy != "protect":
            return None

        ip, ua = self._ctx()
        if self.deny_bogons and is_bogon(ip):
            return self._forbidden("Bogon source.")

        token = self._unpack(request.cookies.get(COOKIE_TOKEN, ""))
        if (
            token
            and self._bound(token, ip, ua, self.token_ttl)
            and policy != "challenge"
        ):
            return None

        decision = self._evaluate(ip, ua, policy)
        if decision == "allow":
            return None
        if decision == "deny":
            return self._forbidden("Request denied.")

        return self._issue_challenge(ip, ua)

    def _evaluate(self, ip: str, ua: str, policy: str | None) -> str:
        if policy == "challenge" or policy == "block":
            return "challenge"

        headers = {k.lower(): v for k, v in request.headers.items()}
        score = self.crawler_weight if is_crawler(ua) else 0

        for rule in self.rules:
            if not rule.matches(request.path, request.method, ua, headers, ip):
                continue
            if rule.action != "weigh":
                return rule.action
            score += rule.weight

        if score >= self.threshold or self.mode == "all":
            return "challenge"

        return "allow"

    def _issue_challenge(self, ip: str, ua: str) -> Response:
        nonce = self._pack(
            {
                "t": int(time.time()),
                "i": _hash(ip),
                "u": _hash(ua),
                "p": request.full_path if request.query_string else request.path,
                "r": secrets.token_urlsafe(12),
            }
        )

        resp = make_response(self._html, 403)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        resp.headers["Cache-Control"] = "no-store, private"
        resp.set_cookie(
            COOKIE_NONCE,
            nonce,
            max_age=self.nonce_ttl,
            httponly=True,
            secure=request.is_secure,
            samesite="Strict",
            path="/",
        )
        return resp

    def _forbidden(self, msg: str) -> Response:
        resp = make_response(msg, 403)
        resp.headers["Content-Type"] = "text/plain; charset=utf-8"
        return resp

    def _verify(self):
        origin = request.headers.get("Origin", "")
        if not origin or urlparse(origin).netloc != request.host:
            return jsonify(ok=False, msg="bad origin"), 400
        if request.headers.get("X-Requested-With") != "nobot":
            return jsonify(ok=False, msg="bad request"), 400

        nonce = self._unpack(request.cookies.get(COOKIE_NONCE, ""))
        if not nonce:
            return jsonify(ok=False, msg="missing nonce"), 400

        ip, ua = self._ctx()
        now = time.time()

        if not self._bound(nonce, ip, ua, self.nonce_ttl):
            return jsonify(ok=False, msg="invalid nonce"), 400

        nonce_id = nonce.get("r", "")
        if not nonce_id or not self._consume(nonce_id, now):
            return jsonify(ok=False, msg="replay"), 400

        signals = request.get_json(silent=True) or {}
        if not self._inspect(signals, ua):
            return jsonify(ok=False, msg="challenge failed"), 403

        token = self._pack(
            {
                "t": int(now),
                "i": _hash(ip),
                "u": _hash(ua),
                "r": secrets.token_urlsafe(8),
            }
        )

        resp = make_response(jsonify(ok=True, next=nonce.get("p") or "/"))
        resp.set_cookie(
            COOKIE_TOKEN,
            token,
            max_age=self.token_ttl,
            httponly=True,
            secure=request.is_secure,
            samesite="Lax",
            path="/",
        )
        resp.set_cookie(
            COOKIE_NONCE,
            "",
            expires=0,
            max_age=0,
            httponly=True,
            secure=request.is_secure,
            samesite="Strict",
            path="/",
        )
        return resp

    def _inspect(self, s: dict, ua: str) -> bool:
        lower = ua.lower()

        if any(x in ua for x in HEADLESS_UA) or is_crawler(ua):
            return False

        if s.get("webdriver") or s.get("automation"):
            return False

        if not s.get("native", True) or not s.get("cookies"):
            return False

        if s.get("languages", 0) < 1 or s.get("permissionsBug"):
            return False

        elapsed = s.get("elapsed", 0)
        if elapsed < 80 or elapsed > 60_000:
            return False

        renderer = (s.get("renderer") or "").lower()
        if "swiftshader" in renderer or "llvmpipe" in renderer:
            return False

        chrome_ua = "chrome" in lower and "firefox" not in lower
        if chrome_ua and not s.get("chrome"):
            return False
        if chrome_ua and not s.get("mobile") and s.get("plugins", 0) == 0:
            return False

        return True
