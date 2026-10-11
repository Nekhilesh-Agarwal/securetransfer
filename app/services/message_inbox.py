from collections import defaultdict
from threading import Lock

MAX_INBOX_MESSAGES = 200


class MessageInbox:
    """Hold ciphertext for the peer until the receiver decrypts it."""

    def __init__(self, max_messages: int = MAX_INBOX_MESSAGES):
        self._items: dict[str, list[dict]] = defaultdict(list)
        self._lock = Lock()
        self.max_messages = max_messages

    def size(self) -> int:
        with self._lock:
            return sum(len(queued) for queued in self._items.values())

    def enqueue(self, session_id: str, payload: dict) -> None:
        with self._lock:
            total = sum(len(queued) for queued in self._items.values())
            if total >= self.max_messages:
                raise OverflowError("Ciphertext inbox is full.")
            self._items[session_id].append(payload)

    def pending(
        self,
        session_id: str | None = None,
        recipient_user_id: int | None = None,
    ) -> list[dict]:
        with self._lock:
            if session_id is None:
                items: list[dict] = []
                for queued in self._items.values():
                    items.extend(queued)
            else:
                items = list(self._items.get(session_id, []))
            if recipient_user_id is None:
                return items
            return [
                item
                for item in items
                if item.get("recipient_user_id") == recipient_user_id
                or (
                    item.get("recipient_user_id") is None
                    and item.get("sender_user_id") != recipient_user_id
                )
            ]

    def dequeue(
        self,
        session_id: str,
        sequence_number: int,
        ciphertext: str | None = None,
    ) -> None:
        with self._lock:
            queued = self._items.get(session_id, [])
            remaining = [
                item
                for item in queued
                if not (
                    item.get("sequence_number") == sequence_number
                    and (
                        ciphertext is None
                        or item.get("ciphertext") == ciphertext
                    )
                )
            ]
            if remaining:
                self._items[session_id] = remaining
            else:
                self._items.pop(session_id, None)

    def clear(self, session_id: str) -> None:
        with self._lock:
            self._items.pop(session_id, None)


message_inbox = MessageInbox()
