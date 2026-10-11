from sqlalchemy import text

from app.database.connection import Base, engine
from app.database.models import (  # noqa: F401
    AuditLog,
    AuthToken,
    Message,
    TrustedDevice,
    User,
    UserIdentity,
)


def migrate_audit_log_columns() -> None:
    """Add optional audit columns without rebuilding existing tables."""

    with engine.connect() as connection:
        columns = {
            row[1]
            for row in connection.execute(text("PRAGMA table_info(audit_logs)"))
        }
        if "actor_id" not in columns:
            connection.execute(
                text("ALTER TABLE audit_logs ADD COLUMN actor_id VARCHAR(100)")
            )
        if "status" not in columns:
            connection.execute(
                text("ALTER TABLE audit_logs ADD COLUMN status VARCHAR(50)")
            )
        connection.commit()


def migrate_admin_and_message_columns() -> None:
    """Add role and encrypted-transfer audit columns to existing SQLite databases."""
    with engine.connect() as connection:
        user_columns = {
            row[1]
            for row in connection.execute(text("PRAGMA table_info(users)"))
        }
        if "is_admin" not in user_columns:
            connection.execute(
                text("ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT 0")
            )

        message_columns = {
            row[1]
            for row in connection.execute(text("PRAGMA table_info(messages)"))
        }
        additions = {
            "sender_user_id": "INTEGER",
            "recipient_user_id": "INTEGER",
            "sent_at": "DATETIME",
            "received_at": "DATETIME",
            "ciphertext_hash": "VARCHAR(64)",
            "ciphertext": "TEXT",
            "nonce": "VARCHAR(64)",
            "filename": "VARCHAR(255)",
            "signature": "TEXT",
            "signature_payload": "TEXT",
            "signature_algorithm": "VARCHAR(100)",
        }
        for column, sql_type in additions.items():
            if column not in message_columns:
                connection.execute(
                    text(f"ALTER TABLE messages ADD COLUMN {column} {sql_type}")
                )
        connection.execute(
            text("UPDATE messages SET sent_at = created_at WHERE sent_at IS NULL")
        )
        connection.commit()


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    migrate_audit_log_columns()
    migrate_admin_and_message_columns()


if __name__ == "__main__":
    init_db()
    print("SecureTransfer database initialized.")
