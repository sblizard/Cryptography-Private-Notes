import pytest

# internal
from private_notes import PrivNotes

# external

# built-in


def test_pad_fixed_basic():
    priv_notes = PrivNotes(password="test")
    message = b"hello"
    padded = priv_notes._pad_fixed(message)
    assert len(padded) == 2048
    assert padded.startswith(message)
    assert padded[5:] == b"\x00" * (2048 - 5)


def test_pad_fixed_exact_length():
    priv_notes = PrivNotes(password="test")
    message = b"a" * 2048
    padded = priv_notes._pad_fixed(message)
    # When message is exactly max_len, it gets an additional full block of nulls
    assert len(padded) == 4096  # 2048 + 2048
    assert padded[:2048] == message
    assert padded[2048:] == b"\x00" * 2048


def test_pad_fixed_exceeding_length():
    priv_notes = PrivNotes(password="test")
    message = b"a" * 2049
    with pytest.raises(ValueError, match="Message too long to pad"):
        priv_notes._pad_fixed(message)


def test_pad_fixed_custom_length():
    priv_notes = PrivNotes(password="test")
    message = b"hello"
    padded = priv_notes._pad_fixed(message, max_len=100)
    assert len(padded) == 100
    assert padded.startswith(message)
    assert padded[5:] == b"\x00" * (100 - 5)


def test_pad_fixed_empty_message():
    priv_notes = PrivNotes(password="test")
    message = b""
    padded = priv_notes._pad_fixed(message)
    assert len(padded) == 2048
    assert padded == b"\x00" * 2048


# Test cases for _unpad_fixed
def test_unpad_fixed_basic():
    priv_notes = PrivNotes(password="test")
    padded = b"hello" + b"\x00" * 2043
    unpadded = priv_notes._unpad_fixed(padded)
    assert unpadded == b"hello"


def test_unpad_fixed_no_padding():
    priv_notes = PrivNotes(password="test")
    padded = b"hello"
    with pytest.raises(ValueError, match="Message is not properly padded"):
        priv_notes._unpad_fixed(padded)


def test_unpad_fixed_custom_length():
    priv_notes = PrivNotes(password="test")
    padded = b"hello" + b"\x00" * 95
    unpadded = priv_notes._unpad_fixed(padded)
    assert unpadded == b"hello"


def test_unpad_fixed_empty_message():
    priv_notes = PrivNotes(password="test")
    padded = b"\x00" * 2048
    unpadded = priv_notes._unpad_fixed(padded)
    assert unpadded == b""


def test_unpad_fixed_max_length_message():
    priv_notes = PrivNotes(password="test")
    # Test unpadding a message that was exactly max length (has extra null block)
    original_message = b"a" * 2048
    padded = original_message + b"\x00" * 2048  # 4096 bytes total
    unpadded = priv_notes._unpad_fixed(padded)
    assert unpadded == original_message


def test_unpad_fixed_improper_padding():
    priv_notes = PrivNotes(password="test")
    padded = b"hello" + b"\x01" * 2043
    with pytest.raises(ValueError, match="Message is not properly padded"):
        priv_notes._unpad_fixed(padded)
