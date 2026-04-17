from .nobot import Rule

DEFAULT_RULES = [
    Rule("cloudflare-workers", "deny", headers={"CF-Worker": ".*"}),
    Rule(
        "known-bad",
        "deny",
        user_agent=r"(Sogou|MJ12bot|AhrefsBot|SemrushBot|DotBot|BLEXBot"
        r"|DataForSeoBot|Bytedance)",
    ),
    Rule(
        "vuln-scanners",
        "deny",
        user_agent=r"(Nmap|Nikto|sqlmap|ZmEu|masscan|WPScan|Acunetix"
        r"|Nessus|dirbuster)",
    ),
    Rule("wp-scanners", "deny", path=r"(wp-login|wp-admin|xmlrpc\.php|wp-config)"),
    Rule(
        "dotfile-probes",
        "deny",
        path=r"/\.(env|git|svn|htaccess|htpasswd|DS_Store|aws)",
    ),
    Rule(
        "shell-probes",
        "deny",
        path=r"(\.(php|cgi|asp|aspx|jsp)$|/cgi-bin/|/shell|/cmd)",
    ),
    Rule("traversal-attempts", "deny", path=r"(\.\./|%2e%2e|%252e)"),
    Rule("well-known", "allow", path=r"^/\.well-known/"),
    Rule("favicon", "allow", path=r"^/favicon\.ico$"),
    Rule("robots-txt", "allow", path=r"^/robots\.txt$"),
    Rule("sitemap", "allow", path=r"^/sitemap(?:[_-]\w+)?\.xml$"),
    Rule("health-checks", "allow", path=r"^/(healthz?|readyz?|livez?|ping|status)$"),
    Rule(
        "search-engines",
        "allow",
        user_agent=r"(Googlebot|Bingbot|DuckDuckBot|Baiduspider"
        r"|YandexBot|Applebot)",
    ),
    Rule(
        "feed-readers",
        "allow",
        user_agent=r"(Feedly|NewsBlur|Miniflux|FreshRSS|Inoreader"
        r"|Feedbin|Tiny Tiny RSS)",
    ),
    Rule(
        "monitoring",
        "allow",
        user_agent=r"(UptimeRobot|Pingdom|StatusCake|Better Uptime|Checkly)",
    ),
    Rule(
        "link-previews",
        "allow",
        user_agent=r"(Slackbot|Discordbot|Twitterbot|facebookexternalhit"
        r"|LinkedInBot|WhatsApp|TelegramBot)",
    ),
    Rule("archive-org", "allow", user_agent=r"(archive\.org_bot|Wayback)"),
    Rule(
        "ai-bots",
        "challenge",
        user_agent=r"(GPTBot|ChatGPT|Claude-Web|Anthropic|CCBot"
        r"|Google-Extended|Bytespider|PetalBot|Diffbot"
        r"|Cohere-ai|PerplexityBot|YouBot)",
    ),
    Rule(
        "headless-browsers",
        "challenge",
        user_agent=r"(HeadlessChrome|PhantomJS|Playwright|Puppeteer|Selenium)",
    ),
    Rule(
        "aggressive-scrapers",
        "challenge",
        user_agent=r"(Scrapy|colly|HttpClient|python-requests|Go-http-client"
        r"|Java/|libwww-perl|mechanize)",
    ),
    Rule("empty-ua", "challenge", user_agent=r"^$"),
    Rule(
        "curl-wget", "weigh", weight=3, user_agent=r"(^curl/|^Wget/|^HTTPie/|^fetch/)"
    ),
    Rule("missing-accept", "weigh", weight=3, missing_headers=["Accept"]),
    Rule(
        "missing-accept-language",
        "weigh",
        weight=2,
        missing_headers=["Accept-Language"],
    ),
    Rule("connection-close", "weigh", weight=2, headers={"Connection": r"^close$"}),
]
