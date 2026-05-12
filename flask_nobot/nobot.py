from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

from flask import Flask, Response, current_app, jsonify, make_response, request
from werkzeug.datastructures import Headers

COOKIE_TOKEN = "_nobot"
COOKIE_NONCE = "_nobot_n"
VERIFY_PATH = "/_nobot/verify"

ACTIONS = {"allow", "deny", "challenge", "weigh"}

HEADLESS_UA = (
    "headlesschrome",
    "phantomjs",
    "electron",
)

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

_URL_IN_UA = re.compile(
    r"(?:^|[+;]|\s-\s)https?://[^\s);,]+",
    re.I,
)

_BROWSER = re.compile(
    r"mozilla/|webkit|gecko|trident|presto"
    r"|khtml|opera[\s/]|links\s|lynx/"
    r"|\((?:windows|macintosh|x11|linux)",
    re.I,
)

_BOGONS = [
    ipaddress.ip_network(network)
    for network in (
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


class PolicyCallable(Protocol):
    _nobot_policy: str

    def __call__(self, *args: Any, **kwargs: Any) -> Any: ...


ResponseValue = Response | tuple[Response, int]


def is_crawler(user_agent: str) -> bool:
    if not user_agent:
        return True

    if _BOT_SIGNAL.search(user_agent):
        return True

    if _KNOWN_TOOL.search(user_agent):
        return True

    if _URL_IN_UA.search(user_agent):
        return True

    return not _BROWSER.search(user_agent)


def is_bogon(ip_address_value: str) -> bool:
    try:
        address = ipaddress.ip_address(ip_address_value)
    except ValueError:
        return True

    return any(address in network for network in _BOGONS)


def _mark(
    policy: str,
) -> Callable[[PolicyCallable], PolicyCallable]:
    def decorator(function: PolicyCallable) -> PolicyCallable:
        function._nobot_policy = policy
        return function

    return decorator


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

    def __post_init__(self) -> None:
        self.action = self.action.lower()

        if self.action not in ACTIONS:
            raise ValueError(f"invalid action: {self.action}")

        self._path = self._compile(self.path)
        self._method = self._compile(self.method, re.I)
        self._user_agent = self._compile(self.user_agent, re.I)

        self._headers = {
            name: re.compile(pattern, re.I) for name, pattern in self.headers.items()
        }

        self._missing = set(self.missing_headers)

        self._networks = [
            ipaddress.ip_network(network, strict=False)
            for network in self.remote_addresses
        ]

    @staticmethod
    def _compile(
        pattern: str | None,
        flags: int = 0,
    ) -> re.Pattern[str] | None:
        if not pattern:
            return None

        try:
            return re.compile(pattern, flags)
        except re.error as error:
            raise ValueError(f"invalid regex: {pattern}") from error

    def matches(
        self,
        path: str,
        method: str,
        user_agent: str,
        headers: Headers,
        ip_address_value: str,
    ) -> bool:
        if self._path and not self._path.search(path):
            return False

        if self._method and not self._method.fullmatch(method):
            return False

        if self._user_agent and not self._user_agent.search(
            user_agent,
        ):
            return False

        for name, pattern in self._headers.items():
            value = headers.get(name)

            if value is None:
                return False

            if not pattern.search(value):
                return False

        for name in self._missing:
            if headers.get(name):
                return False

        if not self._networks:
            return True

        try:
            address = ipaddress.ip_address(ip_address_value)
        except ValueError:
            return False

        return any(address in network for network in self._networks)


class ReplayStore:
    def __init__(self, ttl: int):
        self.ttl = ttl
        self.values: dict[str, float] = {}
        self.lock = threading.Lock()

    def consume(self, value: str) -> bool:
        now = time.monotonic()

        with self.lock:
            self._cleanup(now)

            if value in self.values:
                return False

            self.values[value] = now + self.ttl
            return True

    def _cleanup(self, now: float) -> None:
        expired = [
            value for value, expires_at in self.values.items() if expires_at <= now
        ]

        for value in expired:
            self.values.pop(value, None)


def _base64_encode(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(data)
    return encoded.rstrip(b"=").decode()


def _base64_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _hash(value: str) -> str:
    digest = hashlib.sha256(value.encode()).hexdigest()
    return digest[:16]


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
        self._replay_store = ReplayStore(nonce_ttl)

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        cfg, prefix = app.config, self.prefix

        secret = cfg.get(f"{prefix}SECRET", self.secret)
        secret = secret or cfg.get("SECRET_KEY")

        if not secret:
            raise RuntimeError(
                "NoBot needs a secret " "(arg, NOBOT_SECRET, or SECRET_KEY)"
            )

        self.secret = secret
        self._key = secret.encode() if isinstance(secret, str) else secret

        self.threshold = int(
            cfg.get(
                f"{prefix}THRESHOLD",
                self.threshold,
            )
        )

        self.token_ttl = int(
            cfg.get(
                f"{prefix}TOKEN_TTL",
                self.token_ttl,
            )
        )

        self.nonce_ttl = int(
            cfg.get(
                f"{prefix}NONCE_TTL",
                self.nonce_ttl,
            )
        )

        self.mode = cfg.get(f"{prefix}MODE", self.mode)

        self.trust_proxy = bool(
            cfg.get(
                f"{prefix}TRUST_PROXY",
                self.trust_proxy,
            )
        )

        self.deny_bogons = bool(
            cfg.get(
                f"{prefix}DENY_BOGONS",
                self.deny_bogons,
            )
        )

        self.crawler_weight = int(
            cfg.get(
                f"{prefix}CRAWLER_WEIGHT",
                self.crawler_weight,
            )
        )

        self.rules.extend(cfg.get(f"{prefix}RULES", []))

        template = (Path(__file__).parent / "challenge.html").read_text()

        self._html = template.replace(
            "__URL__",
            json.dumps(VERIFY_PATH),
        )

        app.add_url_rule(
            VERIFY_PATH,
            "_nobot_verify",
            self._verify,
            methods=["POST"],
        )

        app.before_request(self._before_request)
        app.extensions.setdefault("nobot", self)

    def add_rule(self, rule: Rule) -> None:
        self.rules.append(rule)

    def _pack(self, data: dict) -> str:
        payload = json.dumps(
            data,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()

        signature = hmac.new(
            self._key,
            payload,
            hashlib.sha256,
        ).digest()

        return f"{_base64_encode(payload)}." f"{_base64_encode(signature)}"

    def _unpack(self, token: str) -> dict | None:
        if not token or "." not in token:
            return None

        try:
            payload_encoded, signature_encoded = token.split(".", 1)
            payload = _base64_decode(payload_encoded)
            signature = _base64_decode(signature_encoded)
        except ValueError:
            return None

        expected_signature = hmac.new(
            self._key,
            payload,
            hashlib.sha256,
        ).digest()

        if not hmac.compare_digest(
            signature,
            expected_signature,
        ):
            return None

        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return None

    def _ctx(self) -> tuple[str, str]:
        if self.trust_proxy:
            forwarded_for = request.headers.get(
                "X-Forwarded-For",
                "",
            )

            if forwarded_for:
                ip_address_value = forwarded_for.split(
                    ",",
                    1,
                )[0].strip()
            else:
                ip_address_value = request.remote_addr
        else:
            ip_address_value = request.remote_addr

        user_agent = request.headers.get(
            "User-Agent",
            "",
        )

        return ip_address_value or "0.0.0.0", user_agent

    def _policy(self) -> str | None:
        view = current_app.view_functions.get(
            request.endpoint or "",
        )

        return getattr(view, "_nobot_policy", None)

    def _bound(
        self,
        data: dict,
        ip_address_value: str,
        user_agent: str,
        ttl: int,
    ) -> bool:
        issued_at = data.get("t", 0)

        if time.time() - issued_at > ttl:
            return False

        return data.get("i") == _hash(ip_address_value) and data.get("u") == _hash(
            user_agent
        )

    def _before_request(self) -> ResponseValue | None:
        if request.path == VERIFY_PATH:
            return None

        policy = self._policy()

        if policy == "skip":
            return None

        if self.mode == "off" and policy != "protect":
            return None

        ip_address_value, user_agent = self._ctx()

        if self.deny_bogons and is_bogon(ip_address_value):
            return self._forbidden("Bogon source.")

        token = self._unpack(
            request.cookies.get(COOKIE_TOKEN, ""),
        )

        if token:
            valid_token = self._bound(
                token,
                ip_address_value,
                user_agent,
                self.token_ttl,
            )

            if valid_token and policy != "challenge":
                return None

        decision = self._evaluate(
            ip_address_value,
            user_agent,
            policy,
        )

        if decision == "allow":
            return None

        if decision == "deny":
            return self._forbidden("Request denied.")

        return self._issue_challenge(
            ip_address_value,
            user_agent,
        )

    def _evaluate(
        self,
        ip_address_value: str,
        user_agent: str,
        policy: str | None,
    ) -> str:
        if policy == "block":
            return "deny"

        if policy == "challenge":
            return "challenge"

        score = self.crawler_weight if is_crawler(user_agent) else 0

        for rule in self.rules:
            matches = rule.matches(
                request.path,
                request.method,
                user_agent,
                request.headers,
                ip_address_value,
            )

            if not matches:
                continue

            if rule.action != "weigh":
                return rule.action

            score += rule.weight

        if score >= self.threshold:
            return "challenge"

        if self.mode == "all":
            return "challenge"

        return "allow"

    def _issue_challenge(
        self,
        ip_address_value: str,
        user_agent: str,
    ) -> Response:
        nonce = self._pack(
            {
                "t": int(time.time()),
                "i": _hash(ip_address_value),
                "u": _hash(user_agent),
                "p": (request.full_path if request.query_string else request.path),
                "r": secrets.token_urlsafe(12),
            }
        )

        response = make_response(self._html, 403)

        response.headers["Content-Type"] = "text/html; charset=utf-8"

        response.headers["Cache-Control"] = "no-store, private"

        response.set_cookie(
            COOKIE_NONCE,
            nonce,
            max_age=self.nonce_ttl,
            httponly=True,
            secure=request.is_secure,
            samesite="Strict",
            path="/",
        )

        return response

    @staticmethod
    def _forbidden(message: str) -> Response:
        response = make_response(message, 403)

        response.headers["Content-Type"] = "text/plain; charset=utf-8"

        return response

    def _verify(self) -> ResponseValue:
        origin = request.headers.get("Origin", "")

        if not origin:
            return jsonify(ok=False, msg="bad origin"), 400

        if urlparse(origin).netloc != request.host:
            return jsonify(ok=False, msg="bad origin"), 400

        if request.headers.get("X-Requested-With") != "nobot":
            return jsonify(ok=False, msg="bad request"), 400

        nonce = self._unpack(
            request.cookies.get(COOKIE_NONCE, ""),
        )

        if not nonce:
            return jsonify(ok=False, msg="missing nonce"), 400

        ip_address_value, user_agent = self._ctx()

        if not self._bound(
            nonce,
            ip_address_value,
            user_agent,
            self.nonce_ttl,
        ):
            return jsonify(ok=False, msg="invalid nonce"), 400

        nonce_id = nonce.get("r", "")

        if not nonce_id:
            return jsonify(ok=False, msg="replay"), 400

        if not self._replay_store.consume(nonce_id):
            return jsonify(ok=False, msg="replay"), 400

        signals = request.get_json(silent=True) or {}

        if not self._inspect(signals, user_agent):
            return jsonify(ok=False, msg="challenge failed"), 403

        token = self._pack(
            {
                "t": int(time.time()),
                "i": _hash(ip_address_value),
                "u": _hash(user_agent),
                "r": secrets.token_urlsafe(8),
            }
        )

        response = make_response(
            jsonify(
                ok=True,
                next=nonce.get("p") or "/",
            )
        )

        response.set_cookie(
            COOKIE_TOKEN,
            token,
            max_age=self.token_ttl,
            httponly=True,
            secure=request.is_secure,
            samesite="Lax",
            path="/",
        )

        response.set_cookie(
            COOKIE_NONCE,
            "",
            expires=0,
            max_age=0,
            httponly=True,
            secure=request.is_secure,
            samesite="Strict",
            path="/",
        )

        return response

    def _inspect(
        self,
        signals: dict,
        user_agent: str,
    ) -> bool:
        lower_user_agent = user_agent.lower()

        if any(value in lower_user_agent for value in HEADLESS_UA):
            return False

        if is_crawler(user_agent):
            return False

        if signals.get("webdriver"):
            return False

        if signals.get("automation"):
            return False

        if not signals.get("native", True):
            return False

        if not signals.get("cookies"):
            return False

        if signals.get("languages", 0) < 1:
            return False

        if signals.get("permissionsBug"):
            return False

        elapsed = signals.get("elapsed", 0)

        if elapsed < 80 or elapsed > 60_000:
            return False

        renderer = (signals.get("renderer") or "").lower()

        if "swiftshader" in renderer:
            return False

        if "llvmpipe" in renderer:
            return False

        chrome_user_agent = (
            "chrome" in lower_user_agent and "firefox" not in lower_user_agent
        )

        if chrome_user_agent and not signals.get("chrome"):
            return False

        if (
            chrome_user_agent
            and not signals.get("mobile")
            and signals.get("plugins", 0) == 0
        ):
            return False

        return True
