"""Homograph URL guard: script mixing, brand lookalikes, registrable-domain allowlists."""

from __future__ import annotations

import copy
import ipaddress
import re
import threading
import time
import unicodedata
from dataclasses import asdict, dataclass, replace
from urllib.parse import unquote


class UrlGuardError(ValueError):
    """Raised when a URL analysis or feedback operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class UrlVerdict:
    url: str
    host: str
    ascii_host: str
    unicode_host: str
    registrable_domain: str
    scripts: tuple[str, ...]
    brand: str | None
    similarity: float
    risk: str
    reasons: tuple[str, ...]
    redirect_chain: tuple[str, ...]
    cached: bool = False


_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")
_ASCII_LABEL_RE = re.compile(r"^[a-z0-9_-]+$")
_SPECIAL_SCHEMES = frozenset(("http", "https", "ws", "wss", "ftp", "file"))

_DEFAULT_SUFFIXES = (
    "com", "net", "org", "io", "test", "co.uk", "com.cn", "co.jp",
)

_RISK_ORDER = {"low": 0, "medium": 1, "high": 2}
_BRAND_FLOOR = 0.60
_MEDIUM_SIMILARITY = 0.65
_HIGH_SIMILARITY = 0.82


# Characters commonly substituted for ASCII letters in lookalike domains.
_CONFUSABLES = {
    # Cyrillic
    "а": "a", "б": "b", "в": "b", "г": "r", "д": "d", "е": "e",
    "ё": "e", "ж": "x", "з": "3", "и": "u", "й": "u", "к": "k",
    "л": "n", "м": "m", "н": "h", "о": "o", "п": "n", "р": "p",
    "с": "c", "т": "t", "у": "y", "ф": "f", "х": "x", "ц": "u",
    "ч": "y", "ш": "w", "щ": "w", "ъ": "b", "ы": "u", "ь": "b",
    "э": "e", "ю": "io", "я": "r", "ѕ": "s", "і": "i", "ї": "i",
    "ј": "j", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l",
    # Greek
    "α": "a", "β": "b", "γ": "y", "δ": "d", "ε": "e", "ζ": "z",
    "η": "n", "θ": "o", "ι": "i", "κ": "k", "λ": "l", "μ": "m",
    "ν": "v", "ξ": "x", "ο": "o", "π": "p", "ρ": "p", "σ": "o",
    "ς": "s", "τ": "t", "υ": "u", "φ": "f", "χ": "x", "ψ": "y",
    "ω": "w",
    # Latin variants and digits
    "ı": "i", "ł": "l", "ø": "o", "đ": "d", "ð": "d", "þ": "p",
    "æ": "ae", "œ": "oe", "ß": "ss",
    "0": "o", "1": "l", "2": "z", "3": "e", "4": "a", "5": "s",
    "6": "g", "7": "t", "8": "b", "9": "g",
}

_KEYBOARD_ROWS = (
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
)


def _keyboard_neighbours(char: str) -> set[str]:
    char = char.lower()
    for row_index, row in enumerate(_KEYBOARD_ROWS):
        column = row.find(char)
        if column < 0:
            continue
        neighbours = set()
        for dc in (-1, 1):
            index = column + dc
            if 0 <= index < len(row):
                neighbours.add(row[index])
        for other_index in (row_index - 1, row_index + 1):
            if not 0 <= other_index < len(_KEYBOARD_ROWS):
                continue
            other = _KEYBOARD_ROWS[other_index]
            for index in (column - 1, column, column + 1):
                if 0 <= index < len(other):
                    neighbours.add(other[index])
        neighbours.discard(char)
        return neighbours
    return set()


_KEY_NEIGHBOURS = {
    char: _keyboard_neighbours(char)
    for row in _KEYBOARD_ROWS for char in set(row)
}


def _fold_confusables(text: str) -> str:
    folded = "".join(_CONFUSABLES.get(char, char) for char in text.lower())
    return folded.replace("rn", "m").replace("vv", "w").replace("cl", "d")


def _substitution_cost(left: str, right: str) -> float:
    if left == right:
        return 0.0
    if _fold_confusables(left) == _fold_confusables(right):
        return 0.05
    if right in _KEY_NEIGHBOURS.get(left, ()):
        return 0.45
    return 1.0


def _weighted_distance(left: str, right: str) -> float:
    if left == right:
        return 0.0
    if not left:
        return float(len(right))
    if not right:
        return float(len(left))

    previous = [float(index) for index in range(len(right) + 1)]
    for row, left_char in enumerate(left, 1):
        current = [float(row)]
        for column, right_char in enumerate(right, 1):
            insertion = current[column - 1] + 1.0
            deletion = previous[column] + 1.0
            substitution = previous[column - 1] + _substitution_cost(
                left_char, right_char
            )
            current.append(min(insertion, deletion, substitution))
        previous = current
    return previous[-1]


def _tokens(text: str) -> set[str]:
    return {part for part in re.split(r"[^a-z0-9]+", text) if part}


def _similarity(label: str, candidate: str) -> float:
    if not label or not candidate:
        return 0.0
    left = label.lower()
    right = candidate.lower()
    if left == right:
        return 1.0

    folded_left = _fold_confusables(left)
    folded_right = _fold_confusables(right)
    if folded_left == folded_right:
        return 1.0
    if not folded_left or not folded_right:
        return 0.0

    distance = _weighted_distance(folded_left, folded_right)
    scale = max(len(folded_left), len(folded_right), 1)
    score = max(0.0, min(1.0, 1.0 - distance / scale))

    # A brand name embedded as its own token is a strong impersonation signal
    # (for example "paypal-login").
    if len(folded_right) >= 3 and folded_right in _tokens(folded_left):
        score = max(score, 0.92)
    return score


def _script_of_char(char: str) -> str | None:
    codepoint = ord(char)
    if codepoint < 0x80:
        return "Latin" if char.isalpha() else None
    if unicodedata.combining(char):
        return None
    if not char.isalpha():
        return None

    ranges = (
        ("Latin", ((0x00C0, 0x024F), (0x1E00, 0x1EFF), (0x2C60, 0x2C7F),
                   (0xA720, 0xA7FF), (0xAB30, 0xAB6F), (0xFF21, 0xFF3A),
                   (0xFF41, 0xFF5A), (0x1D400, 0x1D7FF))),
        ("Cyrillic", ((0x0400, 0x052F), (0x1C80, 0x1C8F), (0x2DE0, 0x2DFF),
                      (0xA640, 0xA69F))),
        ("Greek", ((0x0370, 0x03FF), (0x1F00, 0x1FFF))),
        ("Arabic", ((0x0600, 0x06FF), (0x0750, 0x077F), (0x08A0, 0x08FF),
                    (0xFB50, 0xFDFF), (0xFE70, 0xFEFF))),
        ("Hebrew", ((0x0590, 0x05FF), (0xFB1D, 0xFB4F))),
        ("Han", ((0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xF900, 0xFAFF),
                 (0x20000, 0x2FA1F))),
        ("Hiragana", ((0x3040, 0x309F),)),
        ("Katakana", ((0x30A0, 0x30FF), (0x31F0, 0x31FF))),
        ("Hangul", ((0x1100, 0x11FF), (0x3130, 0x318F), (0xAC00, 0xD7AF))),
        ("Devanagari", ((0x0900, 0x097F),)),
        ("Thai", ((0x0E00, 0x0E7F),)),
        ("Armenian", ((0x0530, 0x058F),)),
        ("Georgian", ((0x10A0, 0x10FF), (0x2D00, 0x2D2F))),
    )
    for script, spans in ranges:
        for start, end in spans:
            if start <= codepoint <= end:
                return script

    name = unicodedata.name(char, "")
    for script in ("LATIN", "CYRILLIC", "GREEK", "ARABIC", "HEBREW",
                   "HIRAGANA", "KATAKANA", "HANGUL", "DEVANAGARI", "THAI",
                   "ARMENIAN", "GEORGIAN"):
        if script in name:
            return script.title()
    return None


def _scripts_for(host: str) -> tuple[str, ...]:
    scripts = {
        script
        for char in host
        if (script := _script_of_char(char)) is not None
    }
    return tuple(sorted(scripts))


def _coerce_strings(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value)


class HomographUrlGuard:
    """Score URLs for brand impersonation before mail or browser delivery."""

    def __init__(self, *, brands=None, public_suffixes=None,
                 max_redirects: int = 5, report_threshold: int = 3) -> None:
        self._brands: dict[str, dict[str, tuple[str, ...]]] = {}
        for brand, specification in dict(brands or {}).items():
            domains, keywords = self._coerce_brand_spec(specification)
            self._merge_brand(str(brand), domains, keywords)

        if isinstance(public_suffixes, str):
            provided_suffixes = public_suffixes.replace(" ", "").split(",")
        else:
            provided_suffixes = public_suffixes
        raw_suffixes = tuple(provided_suffixes) if provided_suffixes is not None \
            else _DEFAULT_SUFFIXES
        self._suffixes = tuple(
            suffix for suffix in (
                unicodedata.normalize("NFKC", str(item)).strip().lower().strip(".")
                for item in raw_suffixes
            ) if suffix
        )

        self.max_redirects = max(0, int(max_redirects))
        self.report_threshold = max(1, int(report_threshold))
        self._lock = threading.RLock()
        self._version = 0
        self._allowlist: dict[str, float | None] = {}
        self._feedback: dict[str, dict[str, int]] = {}
        self._cache: dict[tuple, UrlVerdict] = {}
        self._stats = {"analyzed": 0, "invalid": 0, "cached": 0}
        self._brand_index = self._build_brand_index(self._brands)

    @staticmethod
    def _coerce_brand_spec(specification):
        if specification is None:
            return (), ()
        if isinstance(specification, str):
            return (specification,), ()
        if isinstance(specification, dict):
            return (
                _coerce_strings(specification.get("domains")),
                _coerce_strings(specification.get("keywords")),
            )
        return _coerce_strings(specification), ()

    def _merge_brand(self, brand: str, domains, keywords) -> None:
        entry = self._brands.setdefault(brand, {"domains": (), "keywords": ()})
        merged_domains = tuple(dict.fromkeys(
            tuple(entry["domains"]) + tuple(str(item) for item in domains)
        ))
        merged_keywords = tuple(dict.fromkeys(
            tuple(entry["keywords"]) + tuple(str(item) for item in keywords)
        ))
        self._brands[brand] = {
            "domains": merged_domains,
            "keywords": merged_keywords,
        }

    # ------------------------------------------------------------------
    # Host and URL parsing
    # ------------------------------------------------------------------
    @staticmethod
    def _invalid(detail: object) -> UrlGuardError:
        return UrlGuardError("INVALID_URL", detail)

    def _parse_url_unlocked(self, url: str) -> dict:
        if not isinstance(url, str):
            raise self._invalid("URL must be a string")
        original = url
        text = url.strip()
        if not text:
            raise self._invalid("empty URL")
        text = text.replace("\t", "").replace("\r", "").replace("\n", "")
        if not text or any(char.isspace() for char in text):
            raise self._invalid("whitespace in URL")
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in text):
            raise self._invalid("control character in URL")

        match = _SCHEME_RE.match(text)
        scheme = None
        if match:
            scheme = match.group(1).lower()
            rest = text[match.end():]
            if scheme in _SPECIAL_SCHEMES:
                # For special schemes browsers treat backslashes as slashes and
                # ignore any run of leading slashes before the authority.
                rest = rest.replace("\\", "/").lstrip("/")
            elif rest.startswith("//"):
                rest = rest[2:]
            else:
                raise self._invalid("URL has no authority")
        else:
            rest = text.replace("\\", "/")
            if rest.startswith("//"):
                rest = rest.lstrip("/")

        end = len(rest)
        for delimiter in "/?#":
            index = rest.find(delimiter)
            if index >= 0:
                end = min(end, index)
        authority = rest[:end]
        if not authority:
            raise self._invalid("URL has no host")

        if "@" in authority:
            host_port = authority.rsplit("@", 1)[1]
        else:
            host_port = authority
        if not host_port:
            raise self._invalid("URL has no host")

        ip_address = None
        if host_port.startswith("["):
            closing = host_port.find("]")
            if closing < 0:
                raise self._invalid("unterminated IPv6 host")
            literal = host_port[1:closing]
            remainder = host_port[closing + 1:]
            if remainder and not remainder.startswith(":"):
                raise self._invalid("invalid IPv6 host")
            if remainder.startswith(":"):
                self._validate_port(remainder[1:])
            try:
                ip_address = ipaddress.ip_address(literal)
            except ValueError as exc:
                raise self._invalid("invalid IPv6 host") from exc
            if ip_address.version != 6:
                raise self._invalid("invalid IPv6 host")
        else:
            if host_port.count(":") > 1:
                raise self._invalid("unbracketed IPv6 host")
            if ":" in host_port:
                host_part, port_text = host_port.rsplit(":", 1)
                self._validate_port(port_text)
            else:
                host_part = host_port
            if not host_part:
                raise self._invalid("URL has no host")
            host_part = unquote(host_part).rstrip(".")
            if not host_part:
                raise self._invalid("URL has no host")
            if any(char in host_part for char in "/\\@:?#[]"):
                raise self._invalid("invalid character in host")
            try:
                ip_address = ipaddress.ip_address(host_part)
            except ValueError:
                ip_address = None

        if ip_address is not None:
            normalized = ip_address.compressed.lower()
            return {
                "input": original,
                "raw_host": normalized,
                "unicode_host": normalized,
                "host": normalized,
                "ascii_host": normalized,
                "scripts": (),
                "nfkc_changed": False,
                "ip": True,
            }

        host_part = host_part.lower()
        labels = host_part.split(".")
        if any(not label for label in labels):
            raise self._invalid("empty host label")
        decoded_labels = []
        for label in labels:
            if label.startswith("xn--"):
                try:
                    decoded = label[4:].encode("ascii").decode("punycode")
                except (UnicodeError, ValueError) as exc:
                    raise self._invalid("invalid punycode label") from exc
                if not decoded or "." in decoded:
                    raise self._invalid("invalid punycode label")
                decoded_labels.append(decoded)
            else:
                decoded_labels.append(label)
        unicode_host = ".".join(decoded_labels).lower()
        if not unicode_host:
            raise self._invalid("URL has no host")

        normalized_host = unicodedata.normalize("NFKC", unicode_host).lower()
        normalized_host = normalized_host.rstrip(".")
        if not normalized_host or ".." in normalized_host \
                or normalized_host.startswith(".") or normalized_host.endswith("."):
            raise self._invalid("invalid normalized host")
        if len(normalized_host) > 253:
            raise self._invalid("host is too long")

        ascii_labels = []
        for label in normalized_host.split("."):
            if not label:
                raise self._invalid("empty host label")
            try:
                encoded_label = label.encode("utf-8")
            except UnicodeError as exc:
                raise self._invalid("invalid host label") from exc
            if len(encoded_label) > 63:
                raise self._invalid("host label is too long")
            if label.isascii():
                if not _ASCII_LABEL_RE.match(label):
                    raise self._invalid("invalid character in host label")
                ascii_labels.append(label)
            else:
                try:
                    ascii_labels.append(
                        "xn--" + label.encode("punycode").decode("ascii")
                    )
                except (UnicodeError, ValueError) as exc:
                    raise self._invalid("cannot encode host label") from exc

        return {
            "input": original,
            "raw_host": host_part,
            "unicode_host": unicode_host,
            "host": normalized_host,
            "ascii_host": ".".join(ascii_labels),
            "scripts": _scripts_for(unicode_host),
            "nfkc_changed": normalized_host != unicode_host,
            "ip": False,
        }

    @staticmethod
    def _validate_port(port_text: str) -> None:
        if port_text == "":
            return
        if not port_text.isdigit():
            raise HomographUrlGuard._invalid("invalid port")
        if int(port_text) > 65535:
            raise HomographUrlGuard._invalid("port is out of range")

    def normalize_host(self, url: str) -> str:
        with self._lock:
            return self._parse_url_unlocked(url)["host"]

    # ------------------------------------------------------------------
    # Public suffix and registrable-domain handling
    # ------------------------------------------------------------------
    def _suffix_length(self, labels: list[str]) -> int:
        best = 0
        for raw_suffix in self._suffixes:
            if raw_suffix.startswith("*."):
                base = raw_suffix[2:].split(".")
                if len(labels) > len(base) and labels[-len(base):] == base:
                    best = max(best, len(base) + 1)
                continue
            suffix = raw_suffix.split(".")
            if len(suffix) <= len(labels) and labels[-len(suffix):] == suffix:
                best = max(best, len(suffix))
        return best or 1

    def _registrable_from_host(self, host: str) -> str:
        host = host.strip().rstrip(".").lower()
        if not host:
            return ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return host
        labels = host.split(".")
        if any(not label for label in labels):
            labels = [label for label in labels if label]
        if not labels:
            return ""
        suffix_length = self._suffix_length(labels)
        if len(labels) <= suffix_length:
            return host
        return ".".join(labels[-(suffix_length + 1):])

    def _label_from_host(self, host: str) -> str | None:
        labels = host.split(".")
        if not labels or not labels[0]:
            return None
        suffix_length = self._suffix_length(labels)
        if len(labels) > suffix_length:
            return labels[-(suffix_length + 1)]
        return labels[0]

    def registrable_domain(self, host: str) -> str:
        with self._lock:
            if not isinstance(host, str):
                raise self._invalid("host must be a string")
            info = self._parse_url_unlocked(host)
            return self._registrable_from_host(info["host"])

    # ------------------------------------------------------------------
    # Brand index and matching
    # ------------------------------------------------------------------
    def _build_brand_index(self, brands: dict) -> dict:
        entries = []
        official: dict[str, frozenset[str]] = {}
        seen = set()
        for brand in sorted(brands):
            entry = brands[brand]
            owned = set()
            for domain in entry["domains"]:
                try:
                    info = self._parse_url_unlocked(str(domain))
                    host = info["host"]
                    registrable = self._registrable_from_host(host)
                    label = self._label_from_host(host)
                except Exception:
                    fallback = unicodedata.normalize(
                        "NFKC", str(domain)
                    ).strip().lower().strip(".")
                    registrable = fallback
                    label = fallback.split(".")[0] if fallback else ""
                if registrable:
                    owned.add(registrable)
                if label:
                    key = (brand, label, "domain")
                    if key not in seen:
                        seen.add(key)
                        entries.append(key)
            official[brand] = frozenset(owned)
            for keyword in entry["keywords"]:
                label = unicodedata.normalize("NFKC", str(keyword)).strip().lower()
                if not label:
                    continue
                key = (brand, label, "keyword")
                if key not in seen:
                    seen.add(key)
                    entries.append(key)
        return {"entries": tuple(entries), "official": official}

    def _match_brand_unlocked(self, label: str | None,
                              registrable: str) -> tuple[str | None, float, bool]:
        for brand, owned in self._brand_index["official"].items():
            if registrable in owned:
                return brand, 1.0, True
        if not label:
            return None, 0.0, False

        best_brand = None
        best_score = 0.0
        for brand, candidate, _kind in self._brand_index["entries"]:
            score = _similarity(label, candidate)
            if score > best_score:
                best_score = score
                best_brand = brand
        if best_brand is None or best_score < _BRAND_FLOOR:
            return None, 0.0, False
        return best_brand, round(min(1.0, best_score), 6), False

    # ------------------------------------------------------------------
    # Allowlist and feedback
    # ------------------------------------------------------------------
    @staticmethod
    def _resolve_now(now: int | None) -> float:
        return float(time.time()) if now is None else now

    def _is_allowlisted_unlocked(self, host: str, now: float) -> bool:
        registrable = self._registrable_from_host(host)
        if registrable not in self._allowlist:
            return False
        expiry = self._allowlist[registrable]
        return expiry is None or now < expiry

    def allowlist(self, domain: str, *, ttl: int | None = None,
                  now: int | None = None) -> None:
        with self._lock:
            if not isinstance(domain, str):
                raise self._invalid("allowlist domain must be a string")
            current = self._resolve_now(now)
            info = self._parse_url_unlocked(domain)
            registrable = self._registrable_from_host(info["host"])
            if ttl is None:
                expiry = None
            else:
                expiry = current + float(ttl)
            self._allowlist[registrable] = expiry
            self._cache.clear()

    def is_allowlisted(self, host: str, *, now: int | None = None) -> bool:
        with self._lock:
            if not isinstance(host, str):
                raise self._invalid("host must be a string")
            current = self._resolve_now(now)
            info = self._parse_url_unlocked(host)
            return self._is_allowlisted_unlocked(info["host"], current)

    def feedback(self, url: str, *, label: str, now: int | None = None) -> dict:
        with self._lock:
            if label not in ("benign", "phishing"):
                raise UrlGuardError("FEEDBACK_INVALID", label)
            try:
                info = self._parse_url_unlocked(url)
            except UrlGuardError:
                self._stats["invalid"] += 1
                raise
            registrable = self._registrable_from_host(info["host"])
            counts = self._feedback.setdefault(
                registrable, {"phishing": 0, "benign": 0}
            )
            counts[label] += 1
            self._cache.clear()
            phishing = counts["phishing"]
            return {
                "registrable_domain": registrable,
                "label": label,
                "phishing": phishing,
                "benign": counts["benign"],
                "threshold": self.report_threshold,
                "risk": "high" if phishing >= self.report_threshold else "low",
            }

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------
    def _analyze_single_unlocked(self, url: str, now: float,
                                 index: int) -> dict:
        info = self._parse_url_unlocked(url)
        host = info["host"]
        registrable = self._registrable_from_host(host)
        scripts = info["scripts"]
        label = self._label_from_host(host)
        brand, similarity, official = self._match_brand_unlocked(label, registrable)
        allowlisted = self._is_allowlisted_unlocked(host, now)
        phishing = self._feedback.get(registrable, {}).get("phishing", 0)

        reasons = []
        mixed_scripts = len(scripts) >= 2
        if info["nfkc_changed"]:
            reasons.append("nfkc_normalized")
        if mixed_scripts:
            reasons.append("mixed_scripts")
        if brand is not None:
            if official:
                reasons.append("official_domain")
            elif similarity >= _HIGH_SIMILARITY:
                reasons.append("brand_impersonation")
            elif similarity >= _MEDIUM_SIMILARITY:
                reasons.append("brand_similarity")
            else:
                reasons.append("weak_brand_similarity")
        if phishing >= self.report_threshold:
            reasons.append(f"community_feedback:{phishing}")
        if allowlisted:
            reasons.append("allowlisted")

        if mixed_scripts:
            risk = "high"
        elif official and info["nfkc_changed"] and info["raw_host"] != host:
            reasons.append("unicode_confusable")
            risk = "high"
        elif allowlisted:
            risk = "low"
        elif phishing >= self.report_threshold:
            risk = "high"
        elif brand is None or official:
            risk = "low"
        elif similarity >= _HIGH_SIMILARITY:
            risk = "high"
        elif similarity >= _MEDIUM_SIMILARITY:
            risk = "medium"
        else:
            risk = "low"

        return {
            "index": index,
            "url": url,
            "host": host,
            "ascii_host": info["ascii_host"],
            "unicode_host": info["unicode_host"],
            "registrable_domain": registrable,
            "scripts": scripts,
            "brand": brand,
            "similarity": similarity,
            "risk": risk,
            "reasons": tuple(dict.fromkeys(reasons)),
            "allowlisted": allowlisted,
        }

    @staticmethod
    def _hop_identity(info: dict) -> tuple:
        """Identity used for host-level cache reuse.

        The pre-NFKC Unicode spelling and its script set are part of the key so
        two hosts that normalize to the same ASCII name cannot share a verdict.
        """
        return (
            info["raw_host"],
            info["unicode_host"],
            info["host"],
            info["ascii_host"],
            info["scripts"],
            info["nfkc_changed"],
        )

    def analyze(self, url: str, *, redirects=None,
                now: int | None = None) -> UrlVerdict:
        with self._lock:
            if not isinstance(url, str):
                self._stats["invalid"] += 1
                raise self._invalid("URL must be a string")
            current = self._resolve_now(now)
            if redirects is None:
                redirect_list: tuple[str, ...] = ()
            elif isinstance(redirects, str):
                redirect_list = (redirects,)
            else:
                redirect_list = tuple(redirects)

            if len(redirect_list) > self.max_redirects:
                raise UrlGuardError(
                    "REDIRECT_LIMIT",
                    {"redirects": len(redirect_list),
                     "max_redirects": self.max_redirects},
                )
            if any(not isinstance(item, str) for item in redirect_list):
                self._stats["invalid"] += 1
                raise self._invalid("redirect targets must be strings")

            cache_key = ("url", url, redirect_list, self._version)
            cached = self._cache.get(cache_key)
            if cached is not None:
                self._stats["analyzed"] += 1
                self._stats["cached"] += 1
                return replace(cached, cached=True)

            chain = (url,) + redirect_list
            try:
                identity = tuple(
                    self._hop_identity(self._parse_url_unlocked(hop))
                    for hop in chain
                )
            except UrlGuardError as exc:
                if exc.code == "INVALID_URL":
                    self._stats["invalid"] += 1
                raise
            host_key = ("hosts", identity, self._version)
            cached_host = self._cache.get(host_key)
            if cached_host is not None:
                self._stats["analyzed"] += 1
                self._stats["cached"] += 1
                return replace(
                    cached_host,
                    url=url,
                    redirect_chain=chain,
                    cached=True,
                )

            hops = []
            try:
                for index, hop in enumerate(chain):
                    hops.append(self._analyze_single_unlocked(hop, current, index))
            except UrlGuardError as exc:
                if exc.code == "INVALID_URL":
                    self._stats["invalid"] += 1
                raise

            worst = max(hops, key=lambda hop: _RISK_ORDER[hop["risk"]])
            reasons = list(worst["reasons"])
            if worst["index"] > 0:
                reasons.append(f"worst_redirect_hop:{worst['index']}")

            verdict = UrlVerdict(
                url=url,
                host=worst["host"],
                ascii_host=worst["ascii_host"],
                unicode_host=worst["unicode_host"],
                registrable_domain=worst["registrable_domain"],
                scripts=worst["scripts"],
                brand=worst["brand"],
                similarity=worst["similarity"],
                risk=worst["risk"],
                reasons=tuple(dict.fromkeys(reasons)),
                redirect_chain=chain,
                cached=False,
            )
            self._stats["analyzed"] += 1
            if not any(hop["allowlisted"] for hop in hops):
                self._cache[cache_key] = verdict
                self._cache[host_key] = verdict
            return verdict

    def explain(self, url: str, *, now: int | None = None) -> dict:
        return asdict(self.analyze(url, now=now))

    def sweep(self, urls, *, now: int | None = None) -> list[UrlVerdict]:
        results = []
        with self._lock:
            iterable = (urls,) if isinstance(urls, str) else urls
            for url in iterable:
                try:
                    results.append(self.analyze(url, now=now))
                except UrlGuardError as exc:
                    if exc.code == "INVALID_URL":
                        continue
                    raise
        return results

    # ------------------------------------------------------------------
    # Snapshots, brand updates, statistics
    # ------------------------------------------------------------------
    def add_brand(self, brand: str, *, domains=(), keywords=()) -> int:
        with self._lock:
            self._merge_brand(
                str(brand), _coerce_strings(domains), _coerce_strings(keywords)
            )
            self._version += 1
            self._brand_index = self._build_brand_index(self._brands)
            self._cache.clear()
            return self._version

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "schema": 1,
                "version": self._version,
                "brands": {
                    brand: {
                        "domains": list(entry["domains"]),
                        "keywords": list(entry["keywords"]),
                    }
                    for brand, entry in self._brands.items()
                },
                "allowlist": dict(self._allowlist),
                "feedback": {
                    domain: dict(counts)
                    for domain, counts in self._feedback.items()
                },
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                if not isinstance(state, dict):
                    raise ValueError("snapshot must be a mapping")
                raw_brands = state.get("brands")
                raw_allowlist = state.get("allowlist")
                raw_feedback = state.get("feedback")
                if not isinstance(raw_brands, dict):
                    raise ValueError("brands must be a mapping")
                if not isinstance(raw_allowlist, dict):
                    raise ValueError("allowlist must be a mapping")
                if not isinstance(raw_feedback, dict):
                    raise ValueError("feedback must be a mapping")
                version = state.get("version", 0)
                if isinstance(version, bool) or not isinstance(version, int) \
                        or version < 0:
                    raise ValueError("invalid version")

                new_brands = {}
                for brand, entry in raw_brands.items():
                    if not isinstance(brand, str) or not brand:
                        raise ValueError("invalid brand name")
                    if not isinstance(entry, dict):
                        raise ValueError("invalid brand entry")
                    domains = entry.get("domains", ())
                    keywords = entry.get("keywords", ())
                    if not isinstance(domains, (list, tuple)) \
                            or not all(isinstance(item, str) for item in domains):
                        raise ValueError("invalid brand domains")
                    if not isinstance(keywords, (list, tuple)) \
                            or not all(isinstance(item, str) for item in keywords):
                        raise ValueError("invalid brand keywords")
                    new_brands[brand] = {
                        "domains": tuple(domains),
                        "keywords": tuple(keywords),
                    }

                new_allowlist = {}
                for domain, expiry in raw_allowlist.items():
                    if not isinstance(domain, str) or not domain:
                        raise ValueError("invalid allowlist domain")
                    if expiry is not None:
                        if isinstance(expiry, bool) \
                                or not isinstance(expiry, (int, float)):
                            raise ValueError("invalid allowlist expiry")
                    info = self._parse_url_unlocked(domain)
                    registrable = self._registrable_from_host(info["host"])
                    new_allowlist[registrable] = expiry

                new_feedback = {}
                for domain, counts in raw_feedback.items():
                    if not isinstance(domain, str) or not domain:
                        raise ValueError("invalid feedback domain")
                    if not isinstance(counts, dict):
                        raise ValueError("invalid feedback counts")
                    normalized = {}
                    for label in ("phishing", "benign"):
                        value = counts.get(label, 0)
                        if isinstance(value, bool) or not isinstance(value, int) \
                                or value < 0:
                            raise ValueError("invalid feedback count")
                        normalized[label] = value
                    new_feedback[domain] = normalized

                new_index = self._build_brand_index(new_brands)
            except Exception as exc:
                raise UrlGuardError("SNAPSHOT_INVALID", str(exc)) from None

            self._brands = new_brands
            self._allowlist = new_allowlist
            self._feedback = new_feedback
            self._version = version
            self._brand_index = new_index
            self._cache.clear()

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
