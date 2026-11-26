"""In-game mail attachments with capacity checks and idempotent expiry returns."""

from __future__ import annotations

import copy
import inspect
import threading
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass

__all__ = [
    "MailError",
    "AttachmentView",
    "MailView",
    "ClaimResult",
    "ReturnRecord",
    "ExpiryResult",
    "BagView",
    "MailAttachmentClaim",
]


SNAPSHOT_VERSION = 1
SNAPSHOT_KEYS = {"version", "mails", "bags", "returns", "counters", "stats"}
MAIL_KEYS = {
    "mail_id", "sender", "recipient", "attachments",
    "sent_at", "expires_at", "status",
}
ATTACHMENT_KEYS = {
    "attachment_id", "item_id", "count", "slots", "claimed",
}
BAG_KEYS = {"player", "used_slots", "items"}
RETURN_KEYS = {
    "return_id", "mail_id", "sender", "item_id",
    "count", "slots", "returned_at",
}
COUNTER_KEYS = (
    "claims", "claimed_items", "returned_items",
    "expiries", "bag_write_failures",
)
STATS_KEYS = (
    "mails", "active", "empty", "expired", "claims",
    "claimed_items", "returned_items", "expiries", "bag_write_failures",
)

STATUS_ACTIVE = "active"
STATUS_EMPTY = "empty"
STATUS_EXPIRED = "expired"
_MISSING = object()


class MailError(ValueError):
    """Raised when a mail or bag operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class AttachmentView:
    attachment_id: int
    item_id: str
    count: int
    slots: int
    claimed: bool


@dataclass(frozen=True)
class MailView:
    mail_id: str
    sender: str
    recipient: str
    status: str
    attachments: tuple[AttachmentView, ...]
    expires_at: int | None
    claimed_count: int
    unclaimed_count: int


@dataclass(frozen=True)
class ClaimResult:
    mail_id: str
    player: str
    claimed: tuple[AttachmentView, ...]
    slots_used: int
    status: str


@dataclass(frozen=True)
class ReturnRecord:
    return_id: str
    mail_id: str
    sender: str
    item_id: str
    count: int
    slots: int
    returned_at: int


@dataclass(frozen=True)
class ExpiryResult:
    mail_id: str
    returned: tuple[ReturnRecord, ...]
    status: str


@dataclass(frozen=True)
class BagView:
    player: str
    used_slots: int
    free_slots: int
    items: tuple[tuple[str, int], ...]


def _strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _positive_int(value: object) -> bool:
    return _strict_int(value) and value > 0


def _non_negative_int(value: object) -> bool:
    return _strict_int(value) and value >= 0


def _invalid(detail: object) -> MailError:
    return MailError("MAIL_INVALID_REQUEST", detail)


def _snapshot_invalid(detail: object) -> MailError:
    return MailError("MAIL_SNAPSHOT_INVALID", detail)


class MailAttachmentClaim:
    """Deliver attachments, claim them atomically, and return expired items."""

    def __init__(self, *, bag_slots: int = 40, max_attachments: int = 5,
                 default_ttl_ms: int | None = None, bag_writer=None) -> None:
        if not _positive_int(bag_slots):
            raise _invalid("bag_slots must be a positive integer")
        if not _positive_int(max_attachments):
            raise _invalid("max_attachments must be a positive integer")
        if default_ttl_ms is not None and not _positive_int(default_ttl_ms):
            raise _invalid("default_ttl_ms must be a positive integer or None")

        self.bag_slots = bag_slots
        self.max_attachments = max_attachments
        self.default_ttl_ms = default_ttl_ms
        self.bag_writer = bag_writer
        self._lock = threading.RLock()
        self._mails: dict[str, dict] = {}
        self._bags: dict[str, dict] = {}
        self._returns: list[ReturnRecord] = []
        self._counters = {key: 0 for key in COUNTER_KEYS}

    def send_mail(self, mail_id: str, *, sender: str, recipient: str,
                  attachments, sent_at: int,
                  expires_at: int | None = None) -> MailView:
        with self._lock:
            if not isinstance(mail_id, str) or not mail_id:
                raise _invalid("mail_id must be a non-empty string")
            if mail_id in self._mails:
                raise MailError("MAIL_DUPLICATE_ID", {"mail_id": mail_id})
            if not isinstance(sender, str) or not sender.strip():
                raise _invalid("sender must not be empty")
            if not isinstance(recipient, str) or not recipient.strip():
                raise _invalid("recipient must not be empty")
            if not _strict_int(sent_at):
                raise _invalid("sent_at must be an integer millisecond value")

            if expires_at is None and self.default_ttl_ms is not None:
                expires_at = sent_at + self.default_ttl_ms
            if expires_at is not None and (
                not _strict_int(expires_at) or expires_at <= sent_at
            ):
                raise _invalid("expires_at must be later than sent_at")

            mail = {
                "mail_id": mail_id,
                "sender": sender,
                "recipient": recipient,
                "attachments": self._parse_attachments(attachments),
                "sent_at": sent_at,
                "expires_at": expires_at,
                "status": STATUS_ACTIVE,
            }
            self._mails[mail_id] = mail
            return self._mail_view(mail)

    def claim_attachment(self, mail_id: str, *, player: str, attachment_id: int,
                         now: int) -> ClaimResult:
        with self._lock:
            self._require_now(now)
            mail = self._get_mail(mail_id)
            self._require_recipient(mail, player)
            attachment = self._find_attachment(mail, attachment_id)
            if attachment is None:
                raise MailError("MAIL_NOT_FOUND", {
                    "mail_id": mail_id,
                    "attachment_id": attachment_id,
                })
            if attachment["claimed"]:
                raise MailError("MAIL_ALREADY_CLAIMED", {
                    "mail_id": mail_id,
                    "attachment_id": attachment_id,
                })
            if self._is_expired(mail, now):
                raise MailError("MAIL_EXPIRED", {"mail_id": mail_id, "now": now})

            required_slots = attachment["slots"]
            used_slots = self._used_slots(player)
            if used_slots + required_slots > self.bag_slots:
                raise MailError("MAIL_BAG_FULL", {
                    "player": player,
                    "used_slots": used_slots,
                    "required_slots": required_slots,
                    "bag_slots": self.bag_slots,
                })

            claimed = [attachment]
            bag_before = copy.deepcopy(self._bags.get(player))
            self._apply_claim(player, claimed)
            self._write_or_rollback(
                player=player, mail=mail, claimed=claimed,
                slots_used=required_slots, now=now, kind="claim_attachment",
                bag_before=bag_before,
            )

            self._counters["claims"] += 1
            self._counters["claimed_items"] += attachment["count"]
            self._refresh_status(mail)
            return ClaimResult(
                mail_id=mail_id,
                player=player,
                claimed=(self._attachment_view(attachment),),
                slots_used=required_slots,
                status=self._effective_status(mail),
            )

    def claim_all(self, mail_id: str, *, player: str, now: int) -> ClaimResult:
        with self._lock:
            self._require_now(now)
            mail = self._get_mail(mail_id)
            self._require_recipient(mail, player)
            if self._is_expired(mail, now):
                raise MailError("MAIL_EXPIRED", {"mail_id": mail_id, "now": now})

            claimed = [a for a in mail["attachments"] if not a["claimed"]]
            if not claimed:
                raise MailError("MAIL_ALREADY_CLAIMED", {"mail_id": mail_id})

            slots_used = sum(a["slots"] for a in claimed)
            used_slots = self._used_slots(player)
            if used_slots + slots_used > self.bag_slots:
                raise MailError("MAIL_BAG_FULL", {
                    "player": player,
                    "used_slots": used_slots,
                    "required_slots": slots_used,
                    "bag_slots": self.bag_slots,
                })

            bag_before = copy.deepcopy(self._bags.get(player))
            self._apply_claim(player, claimed)
            self._write_or_rollback(
                player=player, mail=mail, claimed=claimed,
                slots_used=slots_used, now=now, kind="claim_all",
                bag_before=bag_before,
            )

            self._counters["claims"] += 1
            self._counters["claimed_items"] += sum(a["count"] for a in claimed)
            mail["status"] = STATUS_EMPTY
            return ClaimResult(
                mail_id=mail_id,
                player=player,
                claimed=tuple(self._attachment_view(a) for a in claimed),
                slots_used=slots_used,
                status=STATUS_EMPTY,
            )

    def expire_mail(self, mail_id: str, *, now: int) -> ExpiryResult:
        with self._lock:
            self._require_now(now)
            return self._expire_mail(self._get_mail(mail_id), now)

    def expire_due(self, *, now: int) -> tuple[ExpiryResult, ...]:
        with self._lock:
            self._require_now(now)
            due_ids = sorted(
                mail_id for mail_id, mail in self._mails.items()
                if mail["status"] != STATUS_EXPIRED and self._due(mail, now)
            )
            return tuple(
                self._expire_mail(self._mails[mail_id], now)
                for mail_id in due_ids
            )

    def mail_view(self, mail_id: str) -> MailView:
        with self._lock:
            return self._mail_view(self._get_mail(mail_id))

    def inbox(self, player: str) -> tuple[MailView, ...]:
        with self._lock:
            mails = sorted(
                (mail for mail in self._mails.values()
                 if mail["recipient"] == player),
                key=lambda mail: mail["mail_id"],
            )
            return tuple(self._mail_view(mail) for mail in mails)

    def bag_of(self, player: str) -> BagView:
        with self._lock:
            return self._bag_view(player)

    def returns_for(self, sender: str) -> tuple[ReturnRecord, ...]:
        with self._lock:
            return tuple(r for r in self._returns if r.sender == sender)

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": SNAPSHOT_VERSION,
                "mails": copy.deepcopy(self._mails),
                "bags": copy.deepcopy(self._bags),
                "returns": [asdict(record) for record in self._returns],
                "counters": dict(self._counters),
                "stats": self._stats(),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                data = copy.deepcopy(state)
            except Exception as exc:
                raise _snapshot_invalid("state is not copyable") from exc
            parsed = self._parse_snapshot(data)
            self._mails = parsed["mails"]
            self._bags = parsed["bags"]
            self._returns = parsed["returns"]
            self._counters = parsed["counters"]

    def stats(self) -> dict:
        with self._lock:
            return self._stats()

    def _parse_attachments(self, attachments) -> list[dict]:
        if (not isinstance(attachments, Sequence)
                or isinstance(attachments, (str, bytes, bytearray))):
            raise _invalid("attachments must be a sequence")
        if len(attachments) == 0:
            raise _invalid("attachments must not be empty")
        if len(attachments) > self.max_attachments:
            raise _invalid("too many attachments")

        parsed = []
        for index, raw in enumerate(attachments, start=1):
            if not isinstance(raw, Mapping):
                raise _invalid(f"attachment {index} must be an object")
            item_id = raw.get("item_id")
            if not isinstance(item_id, str) or not item_id:
                raise _invalid(f"attachment {index} has invalid item_id")
            count = raw.get("count")
            if not _positive_int(count):
                raise _invalid(f"attachment {index} has invalid count")
            slots = raw.get("slots", 1)
            if not _positive_int(slots):
                raise _invalid(f"attachment {index} has invalid slots")
            parsed.append({
                "attachment_id": index,
                "item_id": item_id,
                "count": count,
                "slots": slots,
                "claimed": False,
            })
        return parsed

    def _require_now(self, now: object) -> None:
        if not _strict_int(now):
            raise _invalid("now must be an integer millisecond timestamp")

    def _get_mail(self, mail_id: object) -> dict:
        mail = self._mails.get(mail_id) if isinstance(mail_id, str) else None
        if mail is None:
            raise MailError("MAIL_NOT_FOUND", {"mail_id": mail_id})
        return mail

    @staticmethod
    def _require_recipient(mail: dict, player: object) -> None:
        if player != mail["recipient"]:
            raise MailError("MAIL_NOT_RECIPIENT", {
                "mail_id": mail["mail_id"], "player": player,
            })

    @staticmethod
    def _find_attachment(mail: dict, attachment_id: object):
        if not _strict_int(attachment_id):
            return None
        return next(
            (a for a in mail["attachments"]
             if a["attachment_id"] == attachment_id),
            None,
        )

    @staticmethod
    def _due(mail: dict, now: int) -> bool:
        expires_at = mail["expires_at"]
        return expires_at is not None and now > expires_at

    def _is_expired(self, mail: dict, now: int) -> bool:
        return mail["status"] == STATUS_EXPIRED or self._due(mail, now)

    @staticmethod
    def _attachment_view(attachment: dict) -> AttachmentView:
        return AttachmentView(
            attachment["attachment_id"], attachment["item_id"],
            attachment["count"], attachment["slots"], attachment["claimed"],
        )

    def _mail_view(self, mail: dict) -> MailView:
        attachments = tuple(self._attachment_view(a) for a in mail["attachments"])
        claimed_count = sum(a["claimed"] for a in mail["attachments"])
        return MailView(
            mail_id=mail["mail_id"],
            sender=mail["sender"],
            recipient=mail["recipient"],
            status=self._effective_status(mail),
            attachments=attachments,
            expires_at=mail["expires_at"],
            claimed_count=claimed_count,
            unclaimed_count=len(attachments) - claimed_count,
        )

    @staticmethod
    def _effective_status(mail: dict) -> str:
        if mail["status"] == STATUS_EXPIRED:
            return STATUS_EXPIRED
        if all(a["claimed"] for a in mail["attachments"]):
            return STATUS_EMPTY
        return STATUS_ACTIVE

    @classmethod
    def _refresh_status(cls, mail: dict) -> None:
        if mail["status"] != STATUS_EXPIRED:
            mail["status"] = cls._effective_status(mail)

    def _used_slots(self, player: str) -> int:
        bag = self._bags.get(player)
        return bag["used_slots"] if bag is not None else 0

    def _bag_view(self, player: str) -> BagView:
        bag = self._bags.get(player)
        used_slots = 0 if bag is None else bag["used_slots"]
        items = {} if bag is None else bag["items"]
        return BagView(
            player=player,
            used_slots=used_slots,
            free_slots=self.bag_slots - used_slots,
            items=tuple(sorted(items.items(), key=lambda pair: pair[0])),
        )

    def _apply_claim(self, player: str, claimed: list[dict]) -> None:
        bag = self._bags.setdefault(player, {
            "player": player, "used_slots": 0, "items": {},
        })
        for attachment in claimed:
            attachment["claimed"] = True
            item_id = attachment["item_id"]
            bag["items"][item_id] = bag["items"].get(item_id, 0) + attachment["count"]
            bag["used_slots"] += attachment["slots"]

    def _write_or_rollback(self, *, player: str, mail: dict,
                           claimed: list[dict], slots_used: int,
                           now: int, kind: str, bag_before) -> None:
        try:
            self._call_bag_writer(
                player=player, mail=mail, claimed=claimed,
                slots_used=slots_used, now=now, kind=kind,
            )
        except Exception as exc:
            for attachment in claimed:
                attachment["claimed"] = False
            if bag_before is None:
                self._bags.pop(player, None)
            else:
                self._bags[player] = bag_before
            self._counters["bag_write_failures"] += 1
            if isinstance(exc, MailError):
                raise
            raise MailError("MAIL_BAG_WRITE_FAILED", {
                "player": player,
                "mail_id": mail["mail_id"],
                "error": repr(exc),
            }) from exc

    def _call_bag_writer(self, *, player: str, mail: dict, claimed: list[dict],
                         slots_used: int, now: int, kind: str) -> None:
        writer = self.bag_writer
        if writer is None:
            return
        if not callable(writer):
            for method_name in ("write", "write_bag", "write_items",
                                "record", "save", "persist", "commit"):
                candidate = getattr(writer, method_name, None)
                if callable(candidate):
                    writer = candidate
                    break
            else:
                raise MailError("MAIL_BAG_WRITE_FAILED",
                                {"reason": "bag_writer is not callable"})

        changes = tuple({
            "attachment_id": a["attachment_id"],
            "item_id": a["item_id"],
            "count": a["count"],
            "slots": a["slots"],
        } for a in claimed)
        added: dict[str, int] = {}
        for change in changes:
            added[change["item_id"]] = (
                added.get(change["item_id"], 0) + change["count"]
            )
        bag = self._bag_view(player)
        event = {
            "kind": kind,
            "player": player,
            "mail_id": mail["mail_id"],
            "now": now,
            "at": now,
            "changes": changes,
            "writes": changes,
            "rows": changes,
            "attachments": tuple(self._attachment_view(a) for a in claimed),
            "claimed": tuple(self._attachment_view(a) for a in claimed),
            "items": tuple(sorted(added.items())),
            "item_counts": dict(added),
            "added_items": dict(added),
            "slots_used": slots_used,
            "slots": slots_used,
            "used_slots": bag.used_slots,
            "free_slots": bag.free_slots,
            "bag_items": bag.items,
            "bag_item_counts": dict(bag.items),
            "bag": bag,
        }

        try:
            signature = inspect.signature(writer)
        except (TypeError, ValueError):
            result = writer(event)
        else:
            result = self._invoke_by_signature(writer, signature, event, changes)
        if result is False:
            raise MailError("MAIL_BAG_WRITE_FAILED", {"player": player})

    def _invoke_by_signature(self, writer, signature, event: dict,
                             changes: tuple[dict, ...]):
        parameters = signature.parameters
        if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in parameters.values()):
            return writer(**event)

        if self._per_item_signature(parameters):
            results = []
            for change in changes:
                item_event = dict(event)
                item_event.update(change)
                item_event["items"] = ((change["item_id"], change["count"]),)
                item_event["item_counts"] = {change["item_id"]: change["count"]}
                item_event["added_items"] = dict(item_event["item_counts"])
                item_event["slots_used"] = change["slots"]
                item_event["slots"] = change["slots"]
                results.append(self._bind_or_positional(writer, signature, item_event))
            return results
        return self._bind_or_positional(writer, signature, event)

    @staticmethod
    def _per_item_signature(parameters) -> bool:
        names = {n.lower().replace("_", "") for n in parameters}
        item_names = {"item", "itemid"}
        count_names = {"count", "qty", "quantity"}
        batch_names = {"items", "changes", "writes", "rows", "attachments"}
        return (bool(names & item_names) and bool(names & count_names)
                and not (names & batch_names))

    def _bind_or_positional(self, writer, signature, event: dict):
        kwargs = {}
        for name in signature.parameters:
            value = self._named_writer_value(name, event)
            if value is not _MISSING:
                kwargs[name] = value
        try:
            bound = signature.bind(**kwargs)
        except TypeError:
            args = []
            for parameter in signature.parameters.values():
                if parameter.kind in (inspect.Parameter.VAR_POSITIONAL,
                                      inspect.Parameter.VAR_KEYWORD):
                    continue
                value = self._named_writer_value(parameter.name, event)
                args.append(None if value is _MISSING else value)
            return writer(*args)
        bound.apply_defaults()
        return writer(*bound.args, **bound.kwargs)

    @staticmethod
    def _named_writer_value(name: str, event: dict):
        if name in event:
            return event[name]
        normalized = name.lower().replace("_", "")
        if normalized in {"event", "payload", "record", "data",
                          "context", "request", "write"}:
            return event
        if normalized in {"bag", "bagview", "bagstate", "state"}:
            return event["bag"]
        aliases = {
            "playerid": "player", "uid": "player", "userid": "player",
            "timestamp": "now", "qty": "count", "quantity": "count",
            "item": "item_id", "itemid": "item_id",
            "slot": "slots", "slotcount": "slots",
            "used": "used_slots", "usedslots": "used_slots",
            "free": "free_slots", "freeslots": "free_slots",
        }
        alias = aliases.get(normalized)
        if alias is not None:
            return event.get(alias, _MISSING)
        if normalized in {"changes", "writes", "rows"}:
            return event["changes"]
        return _MISSING

    def _expire_mail(self, mail: dict, now: int) -> ExpiryResult:
        mail_id = mail["mail_id"]
        if mail["status"] == STATUS_EXPIRED:
            return ExpiryResult(mail_id, (), STATUS_EXPIRED)

        returned = []
        for attachment in mail["attachments"]:
            if attachment["claimed"]:
                continue
            record = ReturnRecord(
                return_id=f"{mail_id}:{attachment['attachment_id']}",
                mail_id=mail_id,
                sender=mail["sender"],
                item_id=attachment["item_id"],
                count=attachment["count"],
                slots=attachment["slots"],
                returned_at=now,
            )
            returned.append(record)
            self._returns.append(record)

        mail["status"] = STATUS_EXPIRED
        self._counters["expiries"] += 1
        self._counters["returned_items"] += sum(r.count for r in returned)
        return ExpiryResult(mail_id, tuple(returned), STATUS_EXPIRED)

    def _stats(self) -> dict:
        active = empty = expired = 0
        for mail in self._mails.values():
            status = self._effective_status(mail)
            if status == STATUS_ACTIVE:
                active += 1
            elif status == STATUS_EMPTY:
                empty += 1
            else:
                expired += 1
        return {
            "mails": len(self._mails),
            "active": active,
            "empty": empty,
            "expired": expired,
            "claims": self._counters["claims"],
            "claimed_items": self._counters["claimed_items"],
            "returned_items": self._counters["returned_items"],
            "expiries": self._counters["expiries"],
            "bag_write_failures": self._counters["bag_write_failures"],
        }

    def _parse_snapshot(self, data):
        if not isinstance(data, dict) or set(data) != SNAPSHOT_KEYS:
            raise _snapshot_invalid("top-level keys")
        if not _strict_int(data["version"]) or data["version"] != SNAPSHOT_VERSION:
            raise _snapshot_invalid("version")
        for key in ("mails", "bags", "counters", "stats"):
            if not isinstance(data[key], dict):
                raise _snapshot_invalid(key)
        if not isinstance(data["returns"], list):
            raise _snapshot_invalid("returns")

        mails = self._parse_snapshot_mails(data["mails"])
        expected_bags = self._expected_bags(mails)
        bags = self._parse_snapshot_bags(data["bags"], expected_bags)
        returns = self._parse_snapshot_returns(data["returns"], mails)
        counters = self._parse_counters(data["counters"])

        raw_stats = data["stats"]
        if set(raw_stats) != set(STATS_KEYS):
            raise _snapshot_invalid("stats keys")
        if any(not _non_negative_int(raw_stats[key]) for key in STATS_KEYS):
            raise _snapshot_invalid("stats value")
        if raw_stats != self._stats_from(mails, counters):
            raise _snapshot_invalid("stats mismatch")

        return {"mails": mails, "bags": bags,
                "returns": returns, "counters": counters}

    def _parse_snapshot_mails(self, raw_mails: dict) -> dict[str, dict]:
        mails = {}
        for mail_id, raw_mail in raw_mails.items():
            if not isinstance(mail_id, str) or not mail_id:
                raise _snapshot_invalid("mail key")
            if not isinstance(raw_mail, dict) or set(raw_mail) != MAIL_KEYS:
                raise _snapshot_invalid(f"mail {mail_id} structure")
            if raw_mail["mail_id"] != mail_id:
                raise _snapshot_invalid(f"mail id mismatch {mail_id}")
            if not isinstance(raw_mail["sender"], str) or not raw_mail["sender"]:
                raise _snapshot_invalid(f"mail {mail_id} sender")
            if (not isinstance(raw_mail["recipient"], str)
                    or not raw_mail["recipient"]):
                raise _snapshot_invalid(f"mail {mail_id} recipient")
            if not _strict_int(raw_mail["sent_at"]):
                raise _snapshot_invalid(f"mail {mail_id} sent_at")
            expires_at = raw_mail["expires_at"]
            if expires_at is not None and (
                not _strict_int(expires_at)
                or expires_at <= raw_mail["sent_at"]
            ):
                raise _snapshot_invalid(f"mail {mail_id} expires_at")
            if raw_mail["status"] not in (
                STATUS_ACTIVE, STATUS_EMPTY, STATUS_EXPIRED
            ):
                raise _snapshot_invalid(f"mail {mail_id} status")

            raw_attachments = raw_mail["attachments"]
            if (not isinstance(raw_attachments, list)
                    or not 1 <= len(raw_attachments) <= self.max_attachments):
                raise _snapshot_invalid(f"mail {mail_id} attachments")
            attachments = []
            for expected_id, raw_attachment in enumerate(raw_attachments, 1):
                if (not isinstance(raw_attachment, dict)
                        or set(raw_attachment) != ATTACHMENT_KEYS):
                    raise _snapshot_invalid(f"attachment {mail_id}:{expected_id}")
                if raw_attachment["attachment_id"] != expected_id:
                    raise _snapshot_invalid("attachment id mismatch")
                if (not isinstance(raw_attachment["item_id"], str)
                        or not raw_attachment["item_id"]):
                    raise _snapshot_invalid("attachment item_id")
                if not _positive_int(raw_attachment["count"]):
                    raise _snapshot_invalid("attachment count")
                if not _positive_int(raw_attachment["slots"]):
                    raise _snapshot_invalid("attachment slots")
                if not isinstance(raw_attachment["claimed"], bool):
                    raise _snapshot_invalid("attachment claimed")
                attachments.append(dict(raw_attachment))

            all_claimed = all(a["claimed"] for a in attachments)
            if raw_mail["status"] == STATUS_EMPTY and not all_claimed:
                raise _snapshot_invalid("empty status mismatch")
            if raw_mail["status"] == STATUS_ACTIVE and all_claimed:
                raise _snapshot_invalid("active status mismatch")

            mail = dict(raw_mail)
            mail["attachments"] = attachments
            mails[mail_id] = mail
        return mails

    @staticmethod
    def _expected_bags(mails: dict[str, dict]) -> dict[str, dict]:
        expected = {}
        for mail in mails.values():
            player = mail["recipient"]
            for attachment in mail["attachments"]:
                if not attachment["claimed"]:
                    continue
                bag = expected.setdefault(player, {
                    "player": player, "used_slots": 0, "items": {},
                })
                bag["used_slots"] += attachment["slots"]
                item_id = attachment["item_id"]
                bag["items"][item_id] = (
                    bag["items"].get(item_id, 0) + attachment["count"]
                )
        return expected

    def _parse_snapshot_bags(self, raw_bags: dict, expected: dict[str, dict]):
        bags = {}
        zero_bag = {"used_slots": 0, "items": {}}
        for player, raw_bag in raw_bags.items():
            if not isinstance(player, str) or not player:
                raise _snapshot_invalid("bag key")
            if not isinstance(raw_bag, dict) or set(raw_bag) != BAG_KEYS:
                raise _snapshot_invalid(f"bag {player} structure")
            if raw_bag["player"] != player:
                raise _snapshot_invalid(f"bag player mismatch {player}")
            used_slots = raw_bag["used_slots"]
            if (not _non_negative_int(used_slots)
                    or used_slots > self.bag_slots):
                raise _snapshot_invalid(f"bag {player} used_slots")
            if not isinstance(raw_bag["items"], dict):
                raise _snapshot_invalid(f"bag {player} items")
            items = {}
            for item_id, count in raw_bag["items"].items():
                if not isinstance(item_id, str) or not item_id:
                    raise _snapshot_invalid("bag item_id")
                if not _positive_int(count):
                    raise _snapshot_invalid("bag item count")
                items[item_id] = count
            bag = {"player": player, "used_slots": used_slots, "items": items}
            wanted = expected.get(player, {"player": player, **zero_bag})
            if bag != wanted:
                raise _snapshot_invalid(f"bag {player} mismatch")
            bags[player] = bag

        for player in expected:
            if player not in bags:
                raise _snapshot_invalid(f"missing bag {player}")
        return bags

    @staticmethod
    def _parse_snapshot_returns(raw_returns: list, mails: dict[str, dict]):
        records = []
        seen = set()
        for raw in raw_returns:
            if not isinstance(raw, dict) or set(raw) != RETURN_KEYS:
                raise _snapshot_invalid("return structure")
            return_id = raw["return_id"]
            mail_id = raw["mail_id"]
            if not isinstance(return_id, str) or not isinstance(mail_id, str):
                raise _snapshot_invalid("return identity")
            if return_id in seen:
                raise _snapshot_invalid(f"duplicate return {return_id}")
            seen.add(return_id)
            mail = mails.get(mail_id)
            if mail is None:
                raise _snapshot_invalid(f"return {return_id} mail")
            if ":" not in return_id:
                raise _snapshot_invalid(f"return id {return_id}")
            suffix = return_id.rsplit(":", 1)[1]
            if not suffix.isdigit():
                raise _snapshot_invalid(f"return id {return_id}")
            attachment_id = int(suffix)
            attachment = next(
                (a for a in mail["attachments"]
                 if a["attachment_id"] == attachment_id),
                None,
            )
            if attachment is None or return_id != f"{mail_id}:{attachment_id}":
                raise _snapshot_invalid(f"return {return_id} attachment")
            if not isinstance(raw["sender"], str) or raw["sender"] != mail["sender"]:
                raise _snapshot_invalid(f"return {return_id} sender")
            if (not isinstance(raw["item_id"], str)
                    or raw["item_id"] != attachment["item_id"]):
                raise _snapshot_invalid(f"return {return_id} item")
            if (not _positive_int(raw["count"])
                    or raw["count"] != attachment["count"]):
                raise _snapshot_invalid(f"return {return_id} count")
            if (not _positive_int(raw["slots"])
                    or raw["slots"] != attachment["slots"]):
                raise _snapshot_invalid(f"return {return_id} slots")
            if not _strict_int(raw["returned_at"]):
                raise _snapshot_invalid(f"return {return_id} returned_at")
            if attachment["claimed"] or mail["status"] != STATUS_EXPIRED:
                raise _snapshot_invalid(f"return {return_id} state")
            records.append(ReturnRecord(**raw))
        return records

    @staticmethod
    def _parse_counters(raw_counters: dict) -> dict[str, int]:
        if set(raw_counters) != set(COUNTER_KEYS):
            raise _snapshot_invalid("counters keys")
        counters = {}
        for key in COUNTER_KEYS:
            value = raw_counters[key]
            if not _non_negative_int(value):
                raise _snapshot_invalid(f"counters.{key}")
            counters[key] = value
        return counters

    @staticmethod
    def _stats_from(mails: dict[str, dict], counters: dict[str, int]) -> dict:
        active = empty = expired = 0
        for mail in mails.values():
            if mail["status"] == STATUS_EXPIRED:
                expired += 1
            elif all(a["claimed"] for a in mail["attachments"]):
                empty += 1
            else:
                active += 1
        return {
            "mails": len(mails),
            "active": active,
            "empty": empty,
            "expired": expired,
            **counters,
        }
