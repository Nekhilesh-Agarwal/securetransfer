from app.security.session import SecureSession


class SessionManager:
    """Manage active secure sessions in memory."""

    def __init__(self):
        self._sessions: dict[str, SecureSession] = {}
        self._views: dict[tuple[str, int], SecureSession] = {}
        self._peers: dict[str, tuple[int, int]] = {}

    def add_session(self, session: SecureSession) -> None:
        self._sessions[session.session_id] = session

    def add_session_view(self, session: SecureSession, user_id: int) -> None:
        self._views[(session.session_id, user_id)] = session
        self._sessions.setdefault(session.session_id, session)

    def bind_users(self, session_id: str, user_a: int, user_b: int) -> None:
        self._peers[session_id] = (user_a, user_b)

    def get_session(
        self,
        session_id: str,
        user_id: int | None = None,
    ) -> SecureSession | None:
        if user_id is not None:
            view = self._views.get((session_id, user_id))
            if view is not None:
                return view
        return self._sessions.get(session_id)

    def peer_user_id(self, session_id: str, user_id: int) -> int | None:
        pair = self._peers.get(session_id)
        if pair is None:
            return None
        user_a, user_b = pair
        if user_id == user_a:
            return user_b
        if user_id == user_b:
            return user_a
        return None

    def find_session_between(self, user_a: int, user_b: int) -> str | None:
        pair = tuple(sorted((user_a, user_b)))
        for session_id, users in self._peers.items():
            if tuple(sorted(users)) == pair:
                return session_id
        return None

    def remove_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        self._peers.pop(session_id, None)
        for key in [item for item in self._views if item[0] == session_id]:
            self._views.pop(key, None)

    def has_session(self, session_id: str) -> bool:
        return session_id in self._sessions

    def list_session_ids(self) -> list[str]:
        return list(self._sessions.keys())


session_manager = SessionManager()