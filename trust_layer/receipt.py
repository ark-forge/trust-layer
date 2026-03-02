"""External receipt fetching, hashing, and parsing — PSP-agnostic architecture.

Phase 1: Stripe only. Abstract base class allows adding new PSPs without rewriting.
"""

import hashlib
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("trust_layer.receipt")

# --- Limits ---
MAX_RECEIPT_BYTES = 512_000  # 500 KB
FETCH_TIMEOUT_SECONDS = 10.0
MAX_REDIRECTS = 3


# --- Result dataclass ---

@dataclass
class ReceiptResult:
    """Standardized result from fetching and parsing a receipt."""
    receipt_url: str
    receipt_type: str  # "stripe", "unknown", etc.
    receipt_fetch_status: str  # "fetched" or "failed"
    receipt_fetch_error: Optional[str] = None
    receipt_content_hash: Optional[str] = None  # SHA-256 hex of raw bytes
    parsing_status: str = "not_attempted"  # "success", "failed", "not_attempted"
    parsed_fields: Optional[dict] = field(default_factory=lambda: None)


# --- Abstract PSP parser ---

class ReceiptParser(ABC):
    """Abstract base class for PSP receipt parsers.

    To add a new PSP:
    1. Subclass ReceiptParser
    2. Set `name` and `domains`
    3. Implement `parse(html) -> dict`
    4. Call `register_parser(YourParser())` at module level
    """

    name: str  # e.g. "stripe", "paypal"
    domains: list[str]  # e.g. ["pay.stripe.com", "receipt.stripe.com"]

    @abstractmethod
    def parse(self, html: str) -> dict:
        """Parse receipt HTML into standardized fields.

        Must return a dict with any of: amount (float), currency (str),
        status (str), date (str). Return {} if parsing fails.
        """
        ...


# --- Parser registry ---

_PARSER_REGISTRY: dict[str, ReceiptParser] = {}
_DOMAIN_TO_PARSER: dict[str, str] = {}  # domain -> parser name


def register_parser(parser: ReceiptParser) -> None:
    """Register a receipt parser. Called at module level for each PSP."""
    _PARSER_REGISTRY[parser.name] = parser
    for domain in parser.domains:
        _DOMAIN_TO_PARSER[domain] = parser.name


def get_parser(name: str) -> Optional[ReceiptParser]:
    """Get a parser by name."""
    return _PARSER_REGISTRY.get(name)


def get_registered_domains() -> set[str]:
    """Return all whitelisted domains across all registered parsers."""
    return set(_DOMAIN_TO_PARSER.keys())


# --- Stripe parser implementation ---

class StripeReceiptParser(ReceiptParser):
    """Parser for Stripe receipt pages (pay.stripe.com, receipt.stripe.com)."""

    name = "stripe"
    domains = ["pay.stripe.com", "receipt.stripe.com"]

    # Amount patterns: "$1.00", "€1.00", "£1.00", "1.00 EUR", "1,00 EUR"
    _RE_AMOUNT = re.compile(
        r'(?:[\$\€\£]\s*[\d,]+\.?\d*)|(?:[\d,]+\.?\d*\s*(?:EUR|USD|GBP|CHF|CAD|AUD|JPY))',
        re.IGNORECASE,
    )
    # Currency symbols/codes
    _CURRENCY_MAP = {"$": "usd", "€": "eur", "£": "gbp"}
    _RE_CURRENCY_CODE = re.compile(r'(EUR|USD|GBP|CHF|CAD|AUD|JPY)', re.IGNORECASE)

    # Status patterns
    _RE_STATUS = re.compile(
        r'\b(Paid|succeeded|Payment\s+successful|Payment\s+complete|Received)\b',
        re.IGNORECASE,
    )

    # Date patterns (common Stripe formats — full and abbreviated month names)
    _RE_DATE = re.compile(
        r'(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?'
        r'|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)'
        r'\s+\d{1,2},?\s+\d{4}',
        re.IGNORECASE,
    )
    _RE_DATE_ISO = re.compile(r'\d{4}-\d{2}-\d{2}')
    _RE_DATE_SLASH = re.compile(r'\d{1,2}/\d{1,2}/\d{4}')

    def parse(self, html: str) -> dict:
        """Parse Stripe receipt HTML. Returns {} if amount not found."""
        result = {}

        # Amount
        amount_match = self._RE_AMOUNT.search(html)
        if not amount_match:
            return {}

        amount_str = amount_match.group(0).strip()
        # Extract numeric value
        numeric = re.sub(r'[^\d.,]', '', amount_str)
        # Handle European comma format (1,00 -> 1.00)
        if ',' in numeric and '.' not in numeric:
            numeric = numeric.replace(',', '.')
        elif ',' in numeric and '.' in numeric:
            numeric = numeric.replace(',', '')
        try:
            result["amount"] = float(numeric)
        except ValueError:
            return {}

        # Currency
        for symbol, code in self._CURRENCY_MAP.items():
            if symbol in amount_str:
                result["currency"] = code
                break
        if "currency" not in result:
            code_match = self._RE_CURRENCY_CODE.search(amount_str)
            if code_match:
                result["currency"] = code_match.group(1).lower()

        # Status
        status_match = self._RE_STATUS.search(html)
        if status_match:
            result["status"] = "paid"

        # Date — named month format first (most readable)
        date_match = self._RE_DATE.search(html)
        if date_match:
            result["date"] = date_match.group(0)
        else:
            # ISO dates: take most recent >= 2020 to skip static asset dates
            # (e.g. stripe.js?v=2017-08-21 embedded in receipt HTML)
            iso_candidates = [d for d in self._RE_DATE_ISO.findall(html) if d[:4] >= "2020"]
            if iso_candidates:
                result["date"] = max(iso_candidates)
            else:
                slash_match = self._RE_DATE_SLASH.search(html)
                if slash_match:
                    result["date"] = slash_match.group(0)

        return result


# Register built-in parsers
register_parser(StripeReceiptParser())


# --- URL validation ---

def _validate_receipt_url(url: str) -> tuple[bool, str]:
    """Validate receipt URL: HTTPS only, whitelisted domains only.

    Returns (is_valid, error_message).
    """
    if not url or not isinstance(url, str):
        return False, "Empty or invalid URL"

    parsed = urlparse(url)

    if parsed.scheme != "https":
        return False, f"Only HTTPS allowed, got '{parsed.scheme}'"

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "No hostname in URL"

    allowed_domains = get_registered_domains()
    if hostname not in allowed_domains:
        return False, f"Domain '{hostname}' not in whitelist: {sorted(allowed_domains)}"

    return True, ""


def _detect_receipt_type(url: str) -> str:
    """Detect PSP type from URL domain. Returns parser name or 'unknown'."""
    hostname = (urlparse(url).hostname or "").lower()
    return _DOMAIN_TO_PARSER.get(hostname, "unknown")


# --- Core fetch function ---

async def fetch_receipt(url: str) -> ReceiptResult:
    """Fetch, hash, and parse a receipt URL.

    1. Validate URL (SSRF protection)
    2. HTTP GET with strict limits
    3. SHA-256 hash of raw bytes (THE proof — always valid)
    4. Parse via registered PSP parser
    5. Return ReceiptResult (never raises)
    """
    receipt_type = _detect_receipt_type(url)

    # Validate
    valid, error = _validate_receipt_url(url)
    if not valid:
        return ReceiptResult(
            receipt_url=url,
            receipt_type=receipt_type,
            receipt_fetch_status="failed",
            receipt_fetch_error=error,
        )

    # Fetch
    try:
        async with httpx.AsyncClient(
            timeout=FETCH_TIMEOUT_SECONDS,
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
        ) as client:
            resp = await client.get(
                url,
                headers={"User-Agent": "ArkForge Trust Layer (+https://arkforge.fr)"},
            )

        if resp.status_code != 200:
            return ReceiptResult(
                receipt_url=url,
                receipt_type=receipt_type,
                receipt_fetch_status="failed",
                receipt_fetch_error=f"HTTP {resp.status_code}",
            )

        raw_bytes = resp.content
        if len(raw_bytes) > MAX_RECEIPT_BYTES:
            return ReceiptResult(
                receipt_url=url,
                receipt_type=receipt_type,
                receipt_fetch_status="failed",
                receipt_fetch_error=f"Response too large ({len(raw_bytes)} bytes, max {MAX_RECEIPT_BYTES})",
            )

    except httpx.TimeoutException:
        return ReceiptResult(
            receipt_url=url,
            receipt_type=receipt_type,
            receipt_fetch_status="failed",
            receipt_fetch_error="Timeout",
        )
    except Exception as e:
        return ReceiptResult(
            receipt_url=url,
            receipt_type=receipt_type,
            receipt_fetch_status="failed",
            receipt_fetch_error=f"{type(e).__name__}: {str(e)[:200]}",
        )

    # Hash raw bytes — this is THE proof, valid even if parsing fails
    content_hash = hashlib.sha256(raw_bytes).hexdigest()

    # Parse via registered parser
    parser = _PARSER_REGISTRY.get(receipt_type)
    if parser:
        try:
            html_text = raw_bytes.decode("utf-8", errors="replace")
            parsed = parser.parse(html_text)
            parsing_status = "success" if parsed.get("amount") is not None else "failed"
        except Exception as e:
            logger.warning("Receipt parsing error for %s: %s", receipt_type, e)
            parsed = {}
            parsing_status = "failed"
    else:
        parsed = {}
        parsing_status = "not_attempted"

    return ReceiptResult(
        receipt_url=url,
        receipt_type=receipt_type,
        receipt_fetch_status="fetched",
        receipt_content_hash=content_hash,
        parsing_status=parsing_status,
        parsed_fields=parsed if parsed else None,
    )
