from .nobot import NoBot, Rule, block, challenge, is_bogon, is_crawler, protect, skip
from .presets import DEFAULT_RULES

__version__ = "1.0.0"
__all__ = [
    "NoBot",
    "Rule",
    "skip",
    "protect",
    "challenge",
    "block",
    "is_crawler",
    "is_bogon",
    "DEFAULT_RULES",
    "__version__",
]
