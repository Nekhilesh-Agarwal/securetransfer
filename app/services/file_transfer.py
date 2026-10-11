from pathlib import Path

from app.security.session import SecureSession
from app.services.binary_message import (
    EncryptedBinaryMessage,
    decrypt_binary_message,
    encrypt_binary_message,
)


MAX_FILE_SIZE = 50 * 1024 * 1024


def validate_file_path(
    file_path: str | Path,
) -> Path:
    """
    Validate a source file path.
    """

    path = Path(file_path)

    if not path.exists():
        raise ValueError(
            "File does not exist."
        )

    if not path.is_file():
        raise ValueError(
            "Path is not a file."
        )

    return path


def read_file(
    file_path: str | Path,
) -> bytes:
    """
    Read a file into memory after validation.
    """

    path = validate_file_path(
        file_path
    )

    file_size = path.stat().st_size

    if file_size == 0:
        raise ValueError(
            "File cannot be empty."
        )

    if file_size > MAX_FILE_SIZE:
        raise ValueError(
            "File exceeds the maximum allowed size."
        )

    return path.read_bytes()


def prepare_file_for_transfer(
    session: SecureSession,
    file_path: str | Path,
    message_type: str,
    mime_type: str | None = None,
    filename: str | None = None,
) -> EncryptedBinaryMessage:
    """
    Read and encrypt a file for secure transfer.

    The supplied filename is authenticated as part
    of the AES-GCM associated data.
    """

    path = validate_file_path(
        file_path
    )

    data = read_file(path)

    transfer_filename = (
        filename
        if filename is not None
        else path.name
    )

    return encrypt_binary_message(
        session=session,
        data=data,
        message_type=message_type,
        filename=transfer_filename,
        mime_type=mime_type,
    )


def save_received_file(
    session: SecureSession,
    message: EncryptedBinaryMessage,
    output_directory: str | Path,
    avoid_collision: bool = False,
) -> Path:
    """
    Decrypt a received binary message and safely
    save it to the specified output directory.
    """

    output_dir = Path(
        output_directory
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    if not message.filename:
        raise ValueError(
            "Received file has no filename."
        )

    filename = Path(
        message.filename
    ).name

    if filename != message.filename:
        raise ValueError(
            "Invalid filename."
        )

    if filename in {
        "",
        ".",
        "..",
    }:
        raise ValueError(
            "Invalid filename."
        )

    plaintext = decrypt_binary_message(
        session=session,
        message=message,
    )

    output_path = output_dir / filename

    if output_path.exists() and not avoid_collision:
        raise ValueError(
            "A file with the same name already exists."
        )

    if avoid_collision and output_path.exists():
        original = Path(filename)
        suffix = 1
        while output_path.exists():
            output_path = output_dir / f"{original.stem} ({suffix}){original.suffix}"
            suffix += 1

    output_path.write_bytes(
        plaintext
    )

    return output_path
