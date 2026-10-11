from pathlib import Path

import pytest

from app.security.session import create_session
from app.services.binary_message import (
    encrypt_binary_message,
)
from app.services.file_transfer import (
    MAX_FILE_SIZE,
    prepare_file_for_transfer,
    read_file,
    save_received_file,
    validate_file_path,
)


def test_validate_file_path(tmp_path):
    file_path = tmp_path / "test.txt"

    file_path.write_bytes(
        b"hello sentinel"
    )

    result = validate_file_path(
        file_path
    )

    assert result == file_path


def test_validate_file_path_rejects_missing_file(
    tmp_path,
):
    file_path = tmp_path / "missing.txt"

    with pytest.raises(
        ValueError,
        match="does not exist",
    ):
        validate_file_path(
            file_path
        )


def test_validate_file_path_rejects_directory(
    tmp_path,
):
    directory = tmp_path / "directory"

    directory.mkdir()

    with pytest.raises(
        ValueError,
        match="not a file",
    ):
        validate_file_path(
            directory
        )


def test_read_file(tmp_path):
    file_path = tmp_path / "photo.png"

    original_data = (
        b"\x89PNG\r\n\x1a\n"
        b"fake-image-data"
    )

    file_path.write_bytes(
        original_data
    )

    data = read_file(
        file_path
    )

    assert data == original_data


def test_read_file_rejects_empty_file(
    tmp_path,
):
    file_path = tmp_path / "empty.txt"

    file_path.write_bytes(
        b""
    )

    with pytest.raises(
        ValueError,
        match="cannot be empty",
    ):
        read_file(
            file_path
        )


def test_read_file_rejects_large_file(
    tmp_path,
):
    file_path = tmp_path / "large.bin"

    file_path.write_bytes(
        b"x" * (MAX_FILE_SIZE + 1)
    )

    with pytest.raises(
        ValueError,
        match="maximum allowed size",
    ):
        read_file(
            file_path
        )


def test_prepare_file_for_transfer(
    tmp_path,
):
    sender = create_session(
        b"a" * 32,
        session_id="file-transfer-test",
    )

    file_path = tmp_path / "photo.png"

    original_data = (
        b"\x89PNG\r\n\x1a\n"
        b"fake-image-data"
    )

    file_path.write_bytes(
        original_data
    )

    encrypted = prepare_file_for_transfer(
        session=sender,
        file_path=file_path,
        message_type="image",
        mime_type="image/png",
    )

    assert encrypted.session_id == (
        "file-transfer-test"
    )

    assert encrypted.sequence_number == 0
    assert encrypted.message_type == "image"
    assert encrypted.filename == "photo.png"
    assert encrypted.mime_type == "image/png"
    assert encrypted.file_size == len(
        original_data
    )

    assert encrypted.ciphertext != (
        original_data
    )


def test_save_received_file(
    tmp_path,
):
    sender = create_session(
        b"b" * 32,
        session_id="save-file-test",
    )

    receiver = create_session(
        b"b" * 32,
        session_id="save-file-test",
    )

    original_data = b"audio-data"

    encrypted = encrypt_binary_message(
        sender,
        original_data,
        "audio",
        filename="recording.wav",
        mime_type="audio/wav",
    )

    output_directory = (
        tmp_path / "received"
    )

    output_path = save_received_file(
        session=receiver,
        message=encrypted,
        output_directory=output_directory,
    )

    assert output_path == (
        output_directory / "recording.wav"
    )

    assert output_path.exists()

    assert output_path.read_bytes() == (
        original_data
    )


def test_save_received_file_rejects_path_traversal(
    tmp_path,
):
    sender = create_session(
        b"c" * 32,
        session_id="path-test",
    )

    receiver = create_session(
        b"c" * 32,
        session_id="path-test",
    )

    encrypted = encrypt_binary_message(
        sender,
        b"secret-data",
        "file",
        filename="../secret.txt",
        mime_type="text/plain",
    )

    with pytest.raises(
        ValueError,
        match="Invalid filename",
    ):
        save_received_file(
            session=receiver,
            message=encrypted,
            output_directory=tmp_path / "received",
        )


def test_save_received_file_rejects_missing_filename(
    tmp_path,
):
    sender = create_session(
        b"d" * 32,
        session_id="missing-name-test",
    )

    receiver = create_session(
        b"d" * 32,
        session_id="missing-name-test",
    )

    encrypted = encrypt_binary_message(
        sender,
        b"secret-data",
        "file",
    )

    with pytest.raises(
        ValueError,
        match="no filename",
    ):
        save_received_file(
            session=receiver,
            message=encrypted,
            output_directory=tmp_path / "received",
        )


def test_save_received_file_rejects_duplicate(
    tmp_path,
):
    sender = create_session(
        b"e" * 32,
        session_id="duplicate-test",
    )

    receiver = create_session(
        b"e" * 32,
        session_id="duplicate-test",
    )

    encrypted = encrypt_binary_message(
        sender,
        b"duplicate-data",
        "file",
        filename="document.pdf",
        mime_type="application/pdf",
    )

    output_directory = (
        tmp_path / "received"
    )

    output_directory.mkdir()

    existing_file = (
        output_directory / "document.pdf"
    )

    existing_file.write_bytes(
        b"existing"
    )

    with pytest.raises(
        ValueError,
        match="same name already exists",
    ):
        save_received_file(
            session=receiver,
            message=encrypted,
            output_directory=output_directory,
        )