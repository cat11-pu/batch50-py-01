"""Dependency confusion guard: namespace ownership, lookalike scoring, source priority."""

from __future__ import annotations

import copy
import re
import threading
import time
import unicodedata
from dataclasses import dataclass, replace
from datetime import date, datetime, timezone
from urllib.parse import parse_qsl, urlsplit


NAMESPACE_VIOLATION = "NAMESPACE_VIOLATION"
TYPOSQUAT = "TYPOSQUAT"
UNTRUSTED_SOURCE = "UNTRUSTED_SOURCE"
CAPACITY_EXCEEDED = "CAPACITY_EXCEEDED"
BATCH_REJECTED = "BATCH_REJECTED"
SNAPSHOT_INVALID = "SNAPSHOT_INVALID"
INVALID_POLICY = "INVALID_POLICY"
INVALID_METADATA = "INVALID_METADATA"
INVALID_REQUEST = "INVALID_REQUEST"


class DependencyGuardError(ValueError):
    """Raised when a package verdict or ledger operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Verdict:
    package: str
    ecosystem: str
    version: str
    source: str | None
    decision: str
    reasons: tuple[str, ...]
    similarity: float
    cached: bool = False
    publisher: str | None = None
    publisher_since: int | None = None
    code: str | None = None


_CONFUSABLES = {
    # Cyrillic characters whose lowercase forms resemble Latin characters.
    "а": "a",
    "б": "b",
    "в": "b",
    "г": "r",
    "д": "d",
    "е": "e",
    "ё": "e",
    "ж": "x",
    "з": "z",
    "и": "i",
    "й": "i",
    "к": "k",
    "л": "l",
    "м": "m",
    "н": "h",
    "о": "o",
    "п": "p",
    "р": "r",
    "с": "c",
    "т": "t",
    "у": "y",
    "ф": "f",
    "х": "x",
    "ц": "c",
    "ч": "c",
    "ш": "s",
    "щ": "s",
    "ъ": "b",
    "ы": "y",
    "ь": "b",
    "э": "e",
    "ю": "u",
    "я": "r",
    # Ukrainian / Serbian forms.
    "і": "i",
    "ї": "i",
    "є": "e",
    "ґ": "g",
    "ј": "j",
    "љ": "l",
    "њ": "n",
    "ћ": "c",
    "џ": "d",
    "ѕ": "s",
    "һ": "h",
    "ԁ": "d",
    # Common Greek homoglyphs.
    "α": "a",
    "β": "b",
    "γ": "y",
    "δ": "d",
    "ε": "e",
    "ζ": "z",
    "η": "n",
    "θ": "o",
    "ι": "i",
    "κ": "k",
    "λ": "l",
    "μ": "m",
    "ν": "v",
    "ο": "o",
    "π": "p",
    "ρ": "p",
    "σ": "s",
    "ς": "s",
    "τ": "t",
    "υ": "u",
    "φ": "f",
    "χ": "x",
    "ψ": "p",
    "ω": "w",
}

_VERSION_TOKEN = re.compile(r"(\d+)|([a-z]+)|([^0-9a-z]+)")


def _canonical(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip().casefold()


def _normalize_name(value: str) -> str:
    """Fold lookalike characters and remove separators before comparison."""

    folded = unicodedata.normalize("NFKC", value).casefold()
    folded = "".join(_CONFUSABLES.get(character, character) for character in folded)
    return "".join(
        character for character in folded
        if character not in "-_" and unicodedata.category(character) != "Pd"
    )


def _levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    if len(left) > len(right):
        left, right = right, left

    previous = list(range(len(left) + 1))
    for row, right_char in enumerate(right, 1):
        current = [row]
        for column, left_char in enumerate(left, 1):
            insertion = current[column - 1] + 1
            deletion = previous[column] + 1
            substitution = previous[column - 1] + (left_char != right_char)
            current.append(min(insertion, deletion, substitution))
        previous = current
    return previous[-1]


def _version_key(value: object) -> tuple[tuple[int, object], ...]:
    text = unicodedata.normalize("NFKC", str(value)).strip().casefold()
    return tuple(
        (0, int(token)) if token.isdigit() else (1, token)
        for token in (match.group(0) for match in _VERSION_TOKEN.finditer(text))
    )


def _as_timestamp(value: object, *, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a timestamp")
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return int(value.timestamp())
    if isinstance(value, date):
        return int(datetime(value.year, value.month, value.day,
                            tzinfo=timezone.utc).timestamp())
    if isinstance(value, str) and value.strip():
        try:
            return int(float(value))
        except ValueError:
            try:
                parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return int(parsed.timestamp())
            except ValueError:
                pass
    raise ValueError(f"{field} must be an integer or ISO datetime")


def _to_list(value: object) -> list[object]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _dependency_names(value: object) -> tuple[str, ...]:
    names: list[str] = []
    if isinstance(value, dict):
        values = list(value)
    else:
        values = _to_list(value)
    for item in values:
        if isinstance(item, str):
            name = item
        elif isinstance(item, dict):
            name = item.get("package", item.get("name"))
        else:
            name = None
        if isinstance(name, str) and name.strip():
            names.append(name.strip().casefold())
    return tuple(sorted(set(names)))


def _collect_urls(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        collected: list[str] = []
        for item in value.values():
            collected.extend(_collect_urls(item))
        return collected
    if isinstance(value, (list, tuple, set)):
        collected = []
        for item in value:
            collected.extend(_collect_urls(item))
        return collected
    return []


def _download_urls(metadata: dict) -> tuple[str, ...]:
    urls: list[str] = []
    for key in ("url", "download", "download_url", "dist_url", "tarball",
                "tarball_url", "artifact_url", "artifact_urls", "download_urls",
                "distribution_url", "resolved_url", "package_url", "source_url",
                "release_url", "asset_url", "file_url", "urls"):
        if key not in metadata:
            continue
        urls.extend(_collect_urls(metadata[key]))
    return tuple(sorted(set(urls)))


def _normalize_url(value: str) -> str:
    text = value.strip()
    try:
        parsed = urlsplit(text)
    except ValueError:
        return text.casefold().rstrip("/")
    if not parsed.scheme and not parsed.netloc:
        return text.casefold().rstrip("/")
    query = tuple(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    path = parsed.path.rstrip("/")
    return "|".join((
        parsed.scheme.casefold(),
        parsed.netloc.casefold(),
        path,
        repr(query),
        parsed.fragment.casefold(),
    ))


class DependencyConfusionGuard:
    """Admit dependencies by namespace, publisher history and source priority."""

    def __init__(self, *, internal_prefix: str = "corp-", similarity_threshold: float = 0.85,
                 publisher_grace_days: int = 30, max_quarantine: int = 100) -> None:
        if not isinstance(internal_prefix, str) or not internal_prefix.strip():
            raise ValueError("internal_prefix must be a non-empty string")
        if not isinstance(similarity_threshold, (int, float)) or isinstance(
                similarity_threshold, bool) or not 0 <= similarity_threshold <= 1:
            raise ValueError("similarity_threshold must be between zero and one")
        if not isinstance(publisher_grace_days, int) or isinstance(
                publisher_grace_days, bool) or publisher_grace_days < 0:
            raise ValueError("publisher_grace_days must be a non-negative integer")
        if not isinstance(max_quarantine, int) or isinstance(
                max_quarantine, bool) or max_quarantine < 0:
            raise ValueError("max_quarantine must be a non-negative integer")

        self.internal_prefix = internal_prefix
        self.similarity_threshold = float(similarity_threshold)
        self.publisher_grace_days = publisher_grace_days
        self.max_quarantine = max_quarantine
        self._lock = threading.RLock()
        self._policy_version = 1
        self._sources: dict[str, dict] = {}
        self._metadata: dict[tuple[str, str, str, str], dict] = {}
        self._allowlist: dict[tuple[str, str], str | None] = {}
        self._quarantine: dict[tuple[str, str, str | None], dict] = {}
        self._cache: dict[tuple, Verdict] = {}
        self._history: dict[tuple[str, str], list[dict]] = {}
        self._evaluations = 0

    @staticmethod
    def _now(value: int | None) -> int:
        return int(time.time()) if value is None else int(value)

    def _policy_payload(self) -> dict:
        return {
            "internal_prefix": self.internal_prefix,
            "similarity_threshold": self.similarity_threshold,
            "publisher_grace_days": self.publisher_grace_days,
            "max_quarantine": self.max_quarantine,
            "policy_version": self._policy_version,
        }

    def add_source(self, name: str, *, priority: int, kind: str = "public") -> None:
        if not isinstance(name, str) or not name.strip():
            raise DependencyGuardError(UNTRUSTED_SOURCE, "source name must be non-empty")
        if not isinstance(priority, int) or isinstance(priority, bool):
            raise DependencyGuardError(UNTRUSTED_SOURCE, "source priority must be an integer")
        if not isinstance(kind, str) or not kind.strip():
            raise DependencyGuardError(UNTRUSTED_SOURCE, "source kind must be non-empty")
        key = name.strip().casefold()
        record = {
            "name": name.strip(),
            "priority": priority,
            "kind": kind.strip().casefold(),
        }
        with self._lock:
            if self._sources.get(key) != record:
                self._sources[key] = record
                self._cache.clear()

    def _normalize_metadata(self, metadata: dict) -> dict:
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be a mapping")
        package = metadata.get("package", metadata.get("name"))
        if not isinstance(package, str) or not package.strip():
            raise ValueError("package is required")
        ecosystem = metadata.get("ecosystem", "pypi")
        if not isinstance(ecosystem, str) or not ecosystem.strip():
            raise ValueError("ecosystem must be a non-empty string")
        version = metadata.get("version")
        if version is None or not str(version).strip():
            raise ValueError("version is required")

        source = metadata.get("source", metadata.get("source_name",
                                                         metadata.get("registry")))
        if source is not None and not isinstance(source, str):
            raise ValueError("source must be a string")
        source = source.strip().casefold() if isinstance(source, str) and source.strip() else None
        display_source = (metadata.get("source", metadata.get("source_name",
                                                               metadata.get("registry")))
                          if source is not None else None)

        publisher = metadata.get("publisher", metadata.get("owner",
                                                           metadata.get("publisher_name")))
        if publisher is not None and not isinstance(publisher, str):
            raise ValueError("publisher must be a string")
        publisher = publisher.strip() if isinstance(publisher, str) and publisher.strip() else None

        since_value = metadata.get("publisher_since",
                                   metadata.get("owner_since",
                                                metadata.get("publisher_changed_at")))
        publisher_since = _as_timestamp(since_value, field="publisher_since")

        dependencies = _dependency_names(
            metadata.get("depends_on", metadata.get("dependencies",
                                                    metadata.get("requires")))
        )
        urls = _download_urls(metadata)

        version_text = str(version).strip()
        return {
            "package": package.strip().casefold(),
            "display_package": package.strip(),
            "ecosystem": ecosystem.strip().casefold(),
            "source": source,
            "display_source": display_source,
            "version": version_text,
            "version_key": _version_key(version_text),
            "publisher": publisher,
            "publisher_since": publisher_since,
            "urls": urls,
            "dependencies": dependencies,
            "raw": copy.deepcopy(metadata),
        }

    def ingest(self, metadata: dict) -> None:
        try:
            record = self._normalize_metadata(metadata)
        except (TypeError, ValueError) as exc:
            raise DependencyGuardError(INVALID_METADATA, str(exc)) from exc

        key = (record["ecosystem"], record["package"], record["source"],
               record["version"])
        with self._lock:
            previous = self._metadata.get(key)
            self._metadata[key] = record
            is_internal = record["package"].startswith(self.internal_prefix.casefold())
            publisher_changed = previous is None or (
                previous.get("publisher") != record.get("publisher")
                or previous.get("publisher_since") != record.get("publisher_since")
            )
            if is_internal or publisher_changed:
                self._cache.clear()
            else:
                self._invalidate_package(record["package"], record["ecosystem"])

    def _invalidate_package(self, package: str, ecosystem: str) -> None:
        keys = [key for key in self._cache
                if key[0] == ecosystem and key[1] == package]
        for key in keys:
            self._cache.pop(key, None)

    def allowlist(self, package: str, *, ecosystem: str = "pypi",
                  note: str | None = None) -> None:
        try:
            package_key = _canonical(package, field="package")
            ecosystem_key = _canonical(ecosystem, field="ecosystem")
        except ValueError as exc:
            raise DependencyGuardError(INVALID_REQUEST, str(exc)) from exc
        if note is not None and not isinstance(note, str):
            raise DependencyGuardError(INVALID_REQUEST, "note must be a string")
        with self._lock:
            self._allowlist[(ecosystem_key, package_key)] = note
            self._invalidate_package(package_key, ecosystem_key)

    def similarity(self, left: str, right: str) -> float:
        if not isinstance(left, str) or not isinstance(right, str):
            raise TypeError("similarity arguments must be strings")
        left_normalized = _normalize_name(left)
        right_normalized = _normalize_name(right)
        if not left_normalized and not right_normalized:
            return 1.0
        maximum = max(len(left_normalized), len(right_normalized))
        return 1.0 - (_levenshtein(left_normalized, right_normalized) / maximum)

    def _internal_packages(self) -> set[str]:
        prefix = self.internal_prefix.casefold()
        return {
            package for (_, package, _, _) in self._metadata
            if package.startswith(prefix)
        }

    def _similarity_for(self, package: str) -> float:
        internal = self._internal_packages()
        if not internal or package in internal:
            return 0.0
        package_normalized = _normalize_name(package)
        scores = []
        for candidate in internal:
            candidate_normalized = _normalize_name(candidate)
            if not package_normalized and not candidate_normalized:
                scores.append(1.0)
                continue
            maximum = max(len(package_normalized), len(candidate_normalized))
            scores.append(
                1.0 - (_levenshtein(package_normalized, candidate_normalized) / maximum)
            )
        return max(scores, default=0.0)

    def _records(self, package: str, ecosystem: str) -> list[dict]:
        return [
            record for (eco, pkg, _, _), record in self._metadata.items()
            if eco == ecosystem and pkg == package
        ]

    def _select(self, package: str, ecosystem: str,
                version: str | None) -> tuple[dict | None, str, dict | None]:
        records = self._records(package, ecosystem)
        if not records:
            return None, "no_metadata", None

        is_internal = package.startswith(self.internal_prefix.casefold())
        known = []
        for record in records:
            source = record.get("source")
            configuration = self._sources.get(source) if source else None
            if configuration is None:
                continue
            kind = configuration["kind"]
            if is_internal and not (kind == "private" or kind == "internal"
                                    or kind.startswith("private-")):
                continue
            known.append(record)

        if not known:
            return None, "namespace" if is_internal else "untrusted", None

        source_configurations = {
            record["source"]: self._sources[record["source"]] for record in known
        }
        selected_source = min(
            source_configurations,
            key=lambda source: (
                source_configurations[source]["priority"],
                source,
            ),
        )
        source_records = [
            record for record in known if record["source"] == selected_source
        ]
        configuration = source_configurations[selected_source]

        if version is not None:
            version_key = str(version).strip().casefold()
            exact = [record for record in source_records
                     if record["version"].casefold() == version_key]
            if not exact:
                return None, "version_missing", configuration
            selected = min(exact, key=lambda record: (
                record.get("version", "").casefold(),
                record.get("publisher") or "",
            ))
        else:
            selected = max(
                source_records,
                key=lambda record: (
                    record["version_key"],
                    record["version"].casefold(),
                    record.get("publisher") or "",
                ),
            )
        return selected, "ok", configuration

    def _matching_quarantine(self, package: str, ecosystem: str,
                             version: str | None, now: int,
                             *, active_only: bool) -> list[tuple[tuple, dict]]:
        version_key = version.casefold() if isinstance(version, str) else None
        matches = []
        for key, entry in self._quarantine.items():
            if key[0] != ecosystem or key[1] != package:
                continue
            if entry["version"] is not None:
                if version_key is None or entry["version"].casefold() != version_key:
                    continue
            active = entry["expires_at"] > now
            if active_only and not active:
                continue
            matches.append((key, entry))
        return sorted(matches, key=lambda item: (
            item[1]["version"] or "", item[1]["expires_at"], item[1]["reason"]
        ))

    def _publisher_state(self, record: dict | None, now: int) -> tuple[str, bool]:
        if not record:
            return "unknown", False
        since = record.get("publisher_since")
        grace_seconds = self.publisher_grace_days * 86400
        if since is None or grace_seconds <= 0:
            return "mature", False
        elapsed = now - since
        if elapsed <= grace_seconds:
            return "grace", True
        return "mature", False

    def _lock_source_matches(self, record: dict | None, selected_source: str | None,
                             lock_source: str | None) -> bool:
        if lock_source is None:
            return True
        if not isinstance(lock_source, str):
            return False
        text = lock_source.strip()
        if not text:
            return False

        source_key = text.casefold()
        if source_key in self._sources:
            return selected_source == source_key

        record_urls = record.get("urls", ()) if record else ()
        if not record_urls:
            return False
        normalized_lock = _normalize_url(text)
        return any(normalized_lock == _normalize_url(url) for url in record_urls)

    def _time_cache_key(self, record: dict | None, package: str, ecosystem: str,
                        version: str | None, now: int) -> tuple:
        publisher_state, _ = self._publisher_state(record, now)
        quarantines = self._matching_quarantine(
            package, ecosystem, version, now, active_only=False,
        )
        quarantine_state = tuple(
            (key[2], entry["expires_at"] > now, entry["expires_at"], entry["reason"])
            for key, entry in quarantines
        )
        return publisher_state, quarantine_state

    def _build_verdict(self, package: str, ecosystem: str, requested_version: str | None,
                       record: dict | None, status: str, source_configuration: dict | None,
                       lock_source: str | None, now: int, similarity: float,
                       allowed: bool) -> Verdict:
        reasons: list[str] = []
        code: str | None = None
        decision = "allow"
        selected_source = record.get("source") if record else None
        selected_version = record.get("version") if record else None
        is_internal = package.startswith(self.internal_prefix.casefold())

        if not allowed and similarity > self.similarity_threshold:
            decision = "block"
            code = TYPOSQUAT
            reasons.append("typosquat")

        if status != "ok":
            decision = "block"
            if status == "namespace" or (
                    status == "version_missing" and is_internal):
                if code is None:
                    code = NAMESPACE_VIOLATION
                reasons.append("namespace_violation")
            else:
                if code is None:
                    code = UNTRUSTED_SOURCE
                reasons.append(
                    "no_source_metadata" if status == "no_metadata"
                    else "untrusted_source"
                )

        if record is not None and decision != "block":
            active_quarantines = self._matching_quarantine(
                package, ecosystem, selected_version, now, active_only=True,
            )
            if active_quarantines:
                decision = "block"
                code = "QUARANTINED"
                reasons.append("quarantined")

            if decision != "block" and not self._lock_source_matches(
                    record, selected_source, lock_source):
                decision = "block"
                code = UNTRUSTED_SOURCE
                reasons.append("lock_source_mismatch")

            if decision != "block":
                publisher_state, in_grace = self._publisher_state(record, now)
                if in_grace:
                    decision = "confirm"
                    reasons.append("publisher_within_grace_period")
                elif publisher_state == "mature":
                    reasons.append("publisher_stable")

        if allowed:
            reasons.append("allowlisted")
        if decision == "allow":
            reasons.append("admitted")

        return Verdict(
            package=record.get("display_package", package) if record else package,
            ecosystem=ecosystem,
            version=selected_version or (str(requested_version) if requested_version else ""),
            source=selected_source,
            decision=decision,
            reasons=tuple(reasons),
            similarity=float(similarity),
            publisher=record.get("publisher") if record else None,
            publisher_since=record.get("publisher_since") if record else None,
            code=code,
        )

    def evaluate(self, package: str, *, ecosystem: str = "pypi",
                 version: str | None = None, lock_source: str | None = None,
                 now: int | None = None) -> Verdict:
        try:
            package_key = _canonical(package, field="package")
            ecosystem_key = _canonical(ecosystem, field="ecosystem")
        except ValueError as exc:
            raise DependencyGuardError(INVALID_REQUEST, str(exc)) from exc
        if version is not None and not isinstance(version, (str, int)):
            raise DependencyGuardError(INVALID_REQUEST, "version must be a string")
        if lock_source is not None and not isinstance(lock_source, str):
            raise DependencyGuardError(INVALID_REQUEST, "lock_source must be a string")

        requested_version = str(version).strip() if version is not None else None
        current_time = self._now(now)
        display_package = package.strip()

        with self._lock:
            allowed = (ecosystem_key, package_key) in self._allowlist
            similarity = self._similarity_for(package_key)
            record, status, source_configuration = self._select(
                package_key, ecosystem_key, requested_version,
            )
            selected_version = record.get("version") if record else requested_version
            time_key = self._time_cache_key(
                record, package_key, ecosystem_key, selected_version, current_time,
            )
            cache_version = selected_version or ""
            cache_key = (
                ecosystem_key,
                package_key,
                cache_version,
                lock_source.strip() if isinstance(lock_source, str) else "",
                allowed,
                time_key,
            )
            cached = self._cache.get(cache_key)
            if cached is not None:
                result = replace(
                    cached,
                    package=display_package,
                    ecosystem=ecosystem_key,
                    cached=True,
                )
                self._record_history(result, current_time, cached=True)
                return result

            verdict = self._build_verdict(
                package_key, ecosystem_key, requested_version, record, status,
                source_configuration, lock_source, current_time, similarity, allowed,
            )
            verdict = replace(verdict, package=display_package)
            self._evaluations += 1
            self._cache[cache_key] = verdict
            self._record_history(verdict, current_time, cached=False)
            return verdict

    def _record_history(self, verdict: Verdict, now: int, *, cached: bool) -> None:
        key = (verdict.ecosystem, verdict.package.casefold())
        entries = self._history.setdefault(key, [])
        entries.append({
            "now": now,
            "cached": cached,
            "verdict": verdict,
        })
        if len(entries) > 1000:
            del entries[:-1000]

    def _request_nodes(self, requests) -> list[dict]:
        if not isinstance(requests, (list, tuple)):
            raise DependencyGuardError(INVALID_REQUEST, "requests must be a list")
        nodes: list[dict] = []
        identities: set[tuple[str, str]] = set()
        for request in requests:
            if not isinstance(request, dict):
                raise DependencyGuardError(INVALID_REQUEST, "request must be a mapping")
            try:
                package = _canonical(
                    request.get("package", request.get("name")), field="package",
                )
                ecosystem = _canonical(
                    request.get("ecosystem", "pypi"), field="ecosystem",
                )
            except ValueError as exc:
                raise DependencyGuardError(INVALID_REQUEST, str(exc)) from exc
            identity = (ecosystem, package)
            if identity in identities:
                raise DependencyGuardError(
                    INVALID_REQUEST, f"duplicate request for {package}",
                )
            identities.add(identity)
            has_explicit_dependencies = (
                "depends_on" in request or "dependencies" in request
            )
            dependencies = _dependency_names(
                request.get("depends_on", request.get("dependencies"))
            )
            if not has_explicit_dependencies:
                requested_version = request.get("version")
                metadata_dependencies = []
                for record in self._records(package, ecosystem):
                    if requested_version is not None and (
                            record["version"].casefold()
                            != str(requested_version).strip().casefold()):
                        continue
                    metadata_dependencies.extend(record.get("dependencies", ()))
                dependencies = tuple(sorted(set(metadata_dependencies)))
            nodes.append({
                "request": request,
                "package": package,
                "ecosystem": ecosystem,
                "dependencies": dependencies,
            })
        return nodes

    def _ordered_nodes(self, nodes: list[dict]) -> list[dict]:
        by_identity = {(node["ecosystem"], node["package"]): node for node in nodes}
        node_edges: dict[tuple[str, str], set[tuple[str, str]]] = {}
        for node in nodes:
            identity = (node["ecosystem"], node["package"])
            edges = {
                (node["ecosystem"], dependency)
                for dependency in node["dependencies"]
                if (node["ecosystem"], dependency) in by_identity
            }
            node_edges[identity] = edges

        remaining = set(by_identity)
        ordered: list[dict] = []
        while remaining:
            ready = sorted(
                (identity for identity in remaining
                 if not (node_edges[identity] & remaining)),
                key=lambda identity: (identity[1], identity[0]),
            )
            if not ready:
                cycle = sorted(remaining, key=lambda identity: (identity[1], identity[0]))
                raise DependencyGuardError(
                    BATCH_REJECTED,
                    {"package": cycle[0][1], "root": cycle[0][1],
                     "root_package": cycle[0][1], "reason": "dependency_cycle",
                     "cycle": cycle},
                )
            for identity in ready:
                ordered.append(by_identity[identity])
                remaining.remove(identity)
        return ordered

    def resolve_batch(self, requests, *, now: int | None = None) -> list[Verdict]:
        with self._lock:
            nodes = self._request_nodes(requests)
            ordered = self._ordered_nodes(nodes)
            results: list[Verdict] = []
            current_time = self._now(now)
            for node in ordered:
                request = node["request"]
                try:
                    verdict = self.evaluate(
                        request.get("package", request.get("name")),
                        ecosystem=request.get("ecosystem", "pypi"),
                        version=request.get("version"),
                        lock_source=request.get("lock_source"),
                        now=current_time,
                    )
                except DependencyGuardError as exc:
                    raise DependencyGuardError(
                        BATCH_REJECTED,
                        {"package": node["package"], "root": node["package"],
                         "root_package": node["package"], "code": exc.code,
                         "detail": exc.detail},
                    ) from exc
                if verdict.decision == "block":
                    raise DependencyGuardError(
                        BATCH_REJECTED,
                        {"package": verdict.package, "root": verdict.package,
                         "root_package": verdict.package, "code": verdict.code,
                         "reasons": verdict.reasons, "version": verdict.version},
                    )
                results.append(verdict)
            return results

    def quarantine(self, package: str, *, ecosystem: str = "pypi",
                   version: str | None = None, reason: str = "",
                   ttl: int = 86400, now: int | None = None) -> int:
        try:
            package_key = _canonical(package, field="package")
            ecosystem_key = _canonical(ecosystem, field="ecosystem")
        except ValueError as exc:
            raise DependencyGuardError(INVALID_REQUEST, str(exc)) from exc
        if not isinstance(reason, str):
            raise DependencyGuardError(INVALID_REQUEST, "reason must be a string")
        if not isinstance(ttl, int) or isinstance(ttl, bool):
            raise DependencyGuardError(INVALID_REQUEST, "ttl must be an integer")
        version_key = None if version is None else str(version).strip().casefold()
        current_time = self._now(now)
        key = (ecosystem_key, package_key, version_key)

        with self._lock:
            if key not in self._quarantine and len(self._quarantine) >= self.max_quarantine:
                raise DependencyGuardError(
                    CAPACITY_EXCEEDED,
                    {"limit": self.max_quarantine, "package": package_key},
                )
            self._quarantine[key] = {
                "package": package_key,
                "ecosystem": ecosystem_key,
                "version": version_key,
                "reason": reason,
                "expires_at": current_time + ttl,
            }
            self._invalidate_package(package_key, ecosystem_key)
            return len(self._quarantine)

    def release(self, package: str, *, ecosystem: str = "pypi",
                version: str | None = None) -> bool:
        try:
            package_key = _canonical(package, field="package")
            ecosystem_key = _canonical(ecosystem, field="ecosystem")
        except ValueError as exc:
            raise DependencyGuardError(INVALID_REQUEST, str(exc)) from exc
        with self._lock:
            if version is None:
                keys = [key for key in self._quarantine
                        if key[0] == ecosystem_key and key[1] == package_key]
            else:
                version_key = str(version).strip().casefold()
                keys = [
                    (ecosystem_key, package_key, version_key)
                ] if (ecosystem_key, package_key, version_key) in self._quarantine else []
            for key in keys:
                self._quarantine.pop(key, None)
            changed = bool(keys)
            if changed:
                self._invalidate_package(package_key, ecosystem_key)
            return changed

    def purge_expired(self, now: int | None = None) -> int:
        current_time = self._now(now)
        with self._lock:
            expired = [
                key for key, entry in self._quarantine.items()
                if entry["expires_at"] <= current_time
            ]
            for key in expired:
                self._quarantine.pop(key, None)
            if expired:
                self._cache.clear()
            return len(expired)

    def explain(self, package: str, *, ecosystem: str = "pypi") -> dict:
        try:
            package_key = _canonical(package, field="package")
            ecosystem_key = _canonical(ecosystem, field="ecosystem")
        except ValueError as exc:
            raise DependencyGuardError(INVALID_REQUEST, str(exc)) from exc
        with self._lock:
            records = sorted(
                self._records(package_key, ecosystem_key),
                key=lambda record: (
                    record.get("source") or "",
                    record["version_key"],
                    record["version"],
                ),
            )
            quarantines = sorted(
                (entry for key, entry in self._quarantine.items()
                 if key[0] == ecosystem_key and key[1] == package_key),
                key=lambda entry: (
                    entry["version"] or "", entry["expires_at"], entry["reason"],
                ),
            )
            history = list(self._history.get((ecosystem_key, package_key), ()))
            latest = history[-1]["verdict"] if history else None
            return {
                "package": package_key,
                "ecosystem": ecosystem_key,
                "internal": package_key.startswith(self.internal_prefix.casefold()),
                "allowlisted": (ecosystem_key, package_key) in self._allowlist,
                "similarity": self._similarity_for(package_key),
                "decision": latest.decision if latest else None,
                "reasons": latest.reasons if latest else (),
                "last_verdict": copy.deepcopy(latest),
                "sources": copy.deepcopy(records),
                "quarantine": copy.deepcopy(quarantines),
                "history": [copy.deepcopy(item) for item in history],
                "policy_version": self._policy_version,
            }

    def policy(self, **changes) -> dict:
        allowed_changes = {
            "internal_prefix", "similarity_threshold",
            "publisher_grace_days", "max_quarantine",
        }
        unknown = sorted(set(changes) - allowed_changes)
        if unknown:
            raise DependencyGuardError(
                INVALID_POLICY, {"unknown_fields": unknown},
            )

        with self._lock:
            proposed = self._policy_payload()
            for field, value in changes.items():
                if field == "internal_prefix":
                    if not isinstance(value, str) or not value.strip():
                        raise DependencyGuardError(
                            INVALID_POLICY, "internal_prefix must be non-empty",
                        )
                    proposed[field] = value.strip()
                elif field == "similarity_threshold":
                    if not isinstance(value, (int, float)) or isinstance(value, bool) \
                            or not 0 <= value <= 1:
                        raise DependencyGuardError(
                            INVALID_POLICY,
                            "similarity_threshold must be between zero and one",
                        )
                    proposed[field] = float(value)
                elif field in ("publisher_grace_days", "max_quarantine"):
                    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                        raise DependencyGuardError(
                            INVALID_POLICY, f"{field} must be a non-negative integer",
                        )
                    proposed[field] = value

            changed = any(
                proposed[field] != self._policy_payload()[field]
                for field in allowed_changes
            )
            if changed:
                self.internal_prefix = proposed["internal_prefix"]
                self.similarity_threshold = proposed["similarity_threshold"]
                self.publisher_grace_days = proposed["publisher_grace_days"]
                self.max_quarantine = proposed["max_quarantine"]
                self._policy_version += 1
                self._cache.clear()
            return self._policy_payload()

    def snapshot(self) -> dict:
        with self._lock:
            sources = [
                copy.deepcopy(self._sources[key])
                for key in sorted(self._sources)
            ]
            metadata = [
                copy.deepcopy(self._metadata[key])
                for key in sorted(self._metadata)
            ]
            allowlist = [
                {
                    "package": key[1],
                    "ecosystem": key[0],
                    "note": copy.deepcopy(note),
                }
                for key, note in sorted(self._allowlist.items())
            ]
            quarantine = [
                copy.deepcopy(self._quarantine[key])
                for key in sorted(
                    self._quarantine,
                    key=lambda item: (item[0], item[1], item[2] or ""),
                )
            ]
            return copy.deepcopy({
                "version": 1,
                "policy": self._policy_payload(),
                "sources": sources,
                "metadata": metadata,
                "allowlist": allowlist,
                "quarantine": quarantine,
                "stats": self.stats(),
            })

    def _validated_policy_from_snapshot(self, payload: object) -> dict:
        if not isinstance(payload, dict):
            raise ValueError("policy must be a mapping")
        required = {
            "internal_prefix", "similarity_threshold",
            "publisher_grace_days", "max_quarantine", "policy_version",
        }
        if not required.issubset(payload):
            raise ValueError("policy is missing required fields")
        prefix = payload["internal_prefix"]
        threshold = payload["similarity_threshold"]
        grace = payload["publisher_grace_days"]
        capacity = payload["max_quarantine"]
        version = payload["policy_version"]
        if not isinstance(prefix, str) or not prefix.strip():
            raise ValueError("invalid internal_prefix")
        if not isinstance(threshold, (int, float)) or isinstance(threshold, bool) \
                or not 0 <= threshold <= 1:
            raise ValueError("invalid similarity_threshold")
        if not isinstance(grace, int) or isinstance(grace, bool) or grace < 0:
            raise ValueError("invalid publisher_grace_days")
        if not isinstance(capacity, int) or isinstance(capacity, bool) or capacity < 0:
            raise ValueError("invalid max_quarantine")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise ValueError("invalid policy_version")
        return {
            "internal_prefix": prefix.strip(),
            "similarity_threshold": float(threshold),
            "publisher_grace_days": grace,
            "max_quarantine": capacity,
            "policy_version": version,
        }

    @staticmethod
    def _validate_source_payload(payload: object) -> tuple[str, dict]:
        if not isinstance(payload, dict):
            raise ValueError("source entry must be a mapping")
        name = payload.get("name")
        priority = payload.get("priority")
        kind = payload.get("kind")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("invalid source name")
        if not isinstance(priority, int) or isinstance(priority, bool):
            raise ValueError("invalid source priority")
        if not isinstance(kind, str) or not kind.strip():
            raise ValueError("invalid source kind")
        return name.strip().casefold(), {
            "name": name.strip(),
            "priority": priority,
            "kind": kind.strip().casefold(),
        }

    @staticmethod
    def _rehydrate_record(item: object) -> dict:
        if not isinstance(item, dict):
            raise ValueError("metadata entry must be a mapping")
        required = {"package", "ecosystem", "version"}
        if not required.issubset(item):
            raise ValueError("metadata entry is missing required fields")
        package = item["package"]
        ecosystem = item["ecosystem"]
        version = item["version"]
        source = item.get("source")
        if not isinstance(package, str) or not package.strip():
            raise ValueError("invalid metadata package")
        if not isinstance(ecosystem, str) or not ecosystem.strip():
            raise ValueError("invalid metadata ecosystem")
        if not isinstance(version, str) or not version.strip():
            raise ValueError("invalid metadata version")
        if source is not None and (not isinstance(source, str) or not source.strip()):
            raise ValueError("invalid metadata source")
        publisher = item.get("publisher")
        if publisher is not None and not isinstance(publisher, str):
            raise ValueError("invalid metadata publisher")
        since = item.get("publisher_since")
        if since is not None and (
                not isinstance(since, int) or isinstance(since, bool)):
            raise ValueError("invalid publisher_since")
        urls = item.get("urls", ())
        if not isinstance(urls, (list, tuple)) or not all(
                isinstance(url, str) for url in urls):
            raise ValueError("invalid metadata urls")
        dependencies = item.get("dependencies", ())
        if not isinstance(dependencies, (list, tuple)) or not all(
                isinstance(dependency, str) for dependency in dependencies):
            raise ValueError("invalid metadata dependencies")
        raw = item.get("raw", {})
        if not isinstance(raw, dict):
            raise ValueError("invalid metadata raw payload")
        return {
            "package": package.strip().casefold(),
            "display_package": item.get("display_package", package.strip()),
            "ecosystem": ecosystem.strip().casefold(),
            "source": source.strip().casefold() if isinstance(source, str) else None,
            "display_source": item.get("display_source", source),
            "version": version.strip(),
            "version_key": _version_key(version),
            "publisher": publisher,
            "publisher_since": since,
            "urls": tuple(sorted(set(str(url) for url in urls))),
            "dependencies": tuple(sorted(set(dependencies))),
            "raw": copy.deepcopy(raw),
        }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                if not isinstance(state, dict):
                    raise ValueError("snapshot must be a mapping")
                required = {
                    "policy", "sources", "metadata",
                    "allowlist", "quarantine", "stats",
                }
                if not required.issubset(state):
                    raise ValueError("snapshot is missing required sections")
                snapshot_version = state.get("version", 1)
                if not isinstance(snapshot_version, int) or isinstance(
                        snapshot_version, bool) or snapshot_version != 1:
                    raise ValueError("unsupported snapshot version")

                policy = self._validated_policy_from_snapshot(state["policy"])

                source_payloads = state["sources"]
                if not isinstance(source_payloads, list):
                    raise ValueError("sources must be a list")
                sources: dict[str, dict] = {}
                for item in source_payloads:
                    key, source = self._validate_source_payload(item)
                    if key in sources:
                        raise ValueError("duplicate source")
                    sources[key] = source

                metadata_payloads = state["metadata"]
                if not isinstance(metadata_payloads, list):
                    raise ValueError("metadata must be a list")
                metadata: dict[tuple[str, str, str, str], dict] = {}
                for item in metadata_payloads:
                    record = self._rehydrate_record(item)
                    key = (record["ecosystem"], record["package"],
                           record["source"], record["version"])
                    if key in metadata:
                        raise ValueError("duplicate metadata entry")
                    metadata[key] = record

                allowlist_payloads = state["allowlist"]
                if not isinstance(allowlist_payloads, list):
                    raise ValueError("allowlist must be a list")
                allowlist: dict[tuple[str, str], str | None] = {}
                for item in allowlist_payloads:
                    if not isinstance(item, dict):
                        raise ValueError("allowlist entry must be a mapping")
                    package = item.get("package")
                    ecosystem = item.get("ecosystem")
                    note = item.get("note")
                    if not isinstance(package, str) or not package.strip():
                        raise ValueError("invalid allowlist package")
                    if not isinstance(ecosystem, str) or not ecosystem.strip():
                        raise ValueError("invalid allowlist ecosystem")
                    if note is not None and not isinstance(note, str):
                        raise ValueError("invalid allowlist note")
                    key = (ecosystem.strip().casefold(), package.strip().casefold())
                    if key in allowlist:
                        raise ValueError("duplicate allowlist entry")
                    allowlist[key] = note

                quarantine_payloads = state["quarantine"]
                if not isinstance(quarantine_payloads, list):
                    raise ValueError("quarantine must be a list")
                quarantine: dict[tuple[str, str, str | None], dict] = {}
                for item in quarantine_payloads:
                    if not isinstance(item, dict):
                        raise ValueError("quarantine entry must be a mapping")
                    package = item.get("package")
                    ecosystem = item.get("ecosystem")
                    version = item.get("version")
                    reason = item.get("reason", "")
                    expires_at = item.get("expires_at")
                    if not isinstance(package, str) or not package.strip():
                        raise ValueError("invalid quarantine package")
                    if not isinstance(ecosystem, str) or not ecosystem.strip():
                        raise ValueError("invalid quarantine ecosystem")
                    if version is not None and (
                            not isinstance(version, str) or not version.strip()):
                        raise ValueError("invalid quarantine version")
                    if not isinstance(reason, str):
                        raise ValueError("invalid quarantine reason")
                    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
                        raise ValueError("invalid quarantine expiry")
                    entry = {
                        "package": package.strip().casefold(),
                        "ecosystem": ecosystem.strip().casefold(),
                        "version": version.strip().casefold() if version else None,
                        "reason": reason,
                        "expires_at": expires_at,
                    }
                    key = (entry["ecosystem"], entry["package"], entry["version"])
                    if key in quarantine:
                        raise ValueError("duplicate quarantine entry")
                    quarantine[key] = entry

                stats_payload = state["stats"]
                if not isinstance(stats_payload, dict):
                    raise ValueError("stats must be a mapping")
                evaluations = stats_payload.get("evaluations")
                quarantined = stats_payload.get("quarantined")
                if not isinstance(evaluations, int) or isinstance(
                        evaluations, bool) or evaluations < 0:
                    raise ValueError("invalid evaluations statistic")
                if not isinstance(quarantined, int) or isinstance(
                        quarantined, bool) or quarantined < 0:
                    raise ValueError("invalid quarantined statistic")
                if quarantined != len(quarantine):
                    raise ValueError("quarantined statistic does not match ledger")
            except Exception as exc:
                raise DependencyGuardError(SNAPSHOT_INVALID, str(exc)) from exc

            self.internal_prefix = policy["internal_prefix"]
            self.similarity_threshold = policy["similarity_threshold"]
            self.publisher_grace_days = policy["publisher_grace_days"]
            self.max_quarantine = policy["max_quarantine"]
            self._policy_version = policy["policy_version"]
            self._sources = sources
            self._metadata = metadata
            self._allowlist = allowlist
            self._quarantine = quarantine
            self._evaluations = evaluations
            self._cache.clear()
            self._history.clear()

    def stats(self) -> dict:
        with self._lock:
            return {
                "evaluations": self._evaluations,
                "quarantined": len(self._quarantine),
            }
