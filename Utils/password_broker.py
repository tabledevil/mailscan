import logging
import weakref
from dataclasses import dataclass


log = logging.getLogger("matt")


@dataclass
class PasswordEntry:
    password: str
    source_struct_ref: object = None


@dataclass
class PendingItem:
    struct_ref: object
    description: str
    try_password: object
    on_unlock: object = None


class PasswordBroker:
    _passwords = []
    _pending = {}
    _used_links = set()

    @classmethod
    def clear(cls):
        cls._passwords.clear()
        cls._pending.clear()
        cls._used_links.clear()

    @classmethod
    def get_passwords(cls):
        return [entry.password for entry in cls._passwords]

    @classmethod
    def register_password(cls, password, source_struct=None):
        normalized = cls._normalize_password(password)
        if not normalized:
            return

        if normalized in {entry.password for entry in cls._passwords}:
            return

        source_ref = cls._make_ref(source_struct) if source_struct is not None else None
        entry = PasswordEntry(password=normalized, source_struct_ref=source_ref)
        cls._passwords.append(entry)

        log.info(
            "Password discovered (%d chars), trying %d pending target(s)",
            len(normalized),
            len(cls._pending),
        )

        for item_id, item in list(cls._pending.items()):
            cls._try_pending(item_id, item, normalized, source_struct)

    @classmethod
    def register_pending(cls, struct, description, try_password_cb, on_unlock=None):
        struct_id = id(struct)
        item = PendingItem(
            struct_ref=cls._make_ref(struct),
            description=description,
            try_password=try_password_cb,
            on_unlock=on_unlock,
        )

        # Try all known passwords immediately.
        for entry in cls._passwords:
            source_struct = (
                entry.source_struct_ref()
                if entry.source_struct_ref is not None
                else None
            )
            if cls._try_pending(struct_id, item, entry.password, source_struct):
                return True

        # Keep it pending for future password discoveries.
        cls._pending[struct_id] = item
        return False

    @classmethod
    def _try_pending(cls, item_id, item, password, source_struct):
        pending_struct = item.struct_ref() if item.struct_ref is not None else None
        if pending_struct is None:
            cls._pending.pop(item_id, None)
            return False

        try:
            unlocked = bool(item.try_password(password))
        except Exception as exc:
            log.debug("Password try callback failed for %s: %s", item.description, exc)
            unlocked = False

        if not unlocked:
            return False

        cls._pending.pop(item_id, None)

        if item.on_unlock is not None:
            try:
                item.on_unlock(password, source_struct)
            except Exception as exc:
                log.debug("on_unlock callback failed for %s: %s", item.description, exc)

        cls._add_source_report(source_struct, item_id, item.description)
        return True

    @classmethod
    def _add_source_report(cls, source_struct, item_id, description):
        if source_struct is None or not hasattr(source_struct, "analyzer"):
            return

        source_id = id(source_struct)
        link = (source_id, item_id)
        if link in cls._used_links:
            return
        cls._used_links.add(link)

        try:
            from structure import Report
        except Exception:
            return

        analyzer = source_struct.analyzer
        if analyzer is None:
            return

        key = f"pw_unlock_{item_id}"
        analyzer.reports[key] = Report(
            f"Discovered password unlocked encrypted object: {description}",
            label="password_unlock",
            rank=1,
            verbosity=0,
        )

    @staticmethod
    def _normalize_password(password):
        if password is None:
            return ""
        return str(password).strip().strip("\"'")

    @staticmethod
    def _make_ref(obj):
        try:
            return weakref.ref(obj)
        except TypeError:
            return lambda: obj
