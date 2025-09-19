# internal
from private_notes import PrivNotes

# external
import pytest

# built-in
import os


def test_encrypt_decrypt_basic():
    priv_notes = PrivNotes(password="test")
    nonce = os.urandom(12)
    title_key = os.urandom(32)  # Generate title key for testing
    plaintext = "hello world"
    ciphertext = priv_notes.encrypt_plaintext(plaintext, nonce, title_key)
    decrypted = priv_notes.decrypt_ciphertext(ciphertext, nonce, title_key)
    assert decrypted == plaintext


def test_encrypt_decrypt_empty_message():
    priv_notes = PrivNotes(password="test")
    nonce = os.urandom(12)
    title_key = os.urandom(32)  # Generate title key for testing
    plaintext = ""
    ciphertext = priv_notes.encrypt_plaintext(plaintext, nonce, title_key)
    decrypted = priv_notes.decrypt_ciphertext(ciphertext, nonce, title_key)
    assert decrypted == plaintext


def test_encrypt_decrypt_max_length():
    priv_notes = PrivNotes(password="test")
    nonce = os.urandom(12)
    title_key = os.urandom(32)  # Generate title key for testing
    plaintext = "a" * 2048  # Full maximum length

    ciphertext = priv_notes.encrypt_plaintext(plaintext, nonce, title_key)
    decrypted = priv_notes.decrypt_ciphertext(ciphertext, nonce, title_key)
    assert decrypted == plaintext


def test_pad_fixed_max_length_gets_extra_block():
    priv_notes = PrivNotes(password="test")
    message = b"a" * 2048
    padded = priv_notes._pad_fixed(message)
    # Should be 2048 + 2048 = 4096 bytes (original message + full null block)
    assert len(padded) == 4096
    assert padded[:2048] == message
    assert padded[2048:] == b"\x00" * 2048


def test_encrypt_plaintext_too_long():
    priv_notes = PrivNotes(password="test")
    nonce = os.urandom(12)
    title_key = os.urandom(32)  # Generate title key for testing
    plaintext = "a" * 2049  # One character over max

    with pytest.raises(ValueError, match="Message too long to pad"):
        priv_notes.encrypt_plaintext(plaintext, nonce, title_key)


def test_decrypt_invalid_nonce():
    priv_notes = PrivNotes(password="test")
    nonce = os.urandom(12)
    title_key = os.urandom(32)  # Generate title key for testing
    invalid_nonce = os.urandom(12)
    plaintext = "hello world"
    ciphertext = priv_notes.encrypt_plaintext(plaintext, nonce, title_key)
    with pytest.raises(Exception):
        priv_notes.decrypt_ciphertext(ciphertext, invalid_nonce, title_key)


def test_decrypt_corrupted_ciphertext():
    priv_notes = PrivNotes(password="test")
    nonce = os.urandom(12)
    title_key = os.urandom(32)  # Generate title key for testing
    plaintext = "hello world"
    ciphertext = priv_notes.encrypt_plaintext(plaintext, nonce, title_key)
    corrupted_ciphertext = ciphertext[:-1] + b"0"
    with pytest.raises(Exception):
        priv_notes.decrypt_ciphertext(corrupted_ciphertext, nonce, title_key)


def test_derive_nonce_basic():
    priv_notes = PrivNotes(password="test")
    title = "note1"
    counter = 1
    nonce = priv_notes._derive_nonce(title, counter)
    assert len(nonce) == 12


def test_derive_nonce_different_titles():
    priv_notes = PrivNotes(password="test")
    counter = 1
    nonce1 = priv_notes._derive_nonce("note1", counter)
    nonce2 = priv_notes._derive_nonce("note2", counter)
    assert nonce1 != nonce2


def test_derive_nonce_different_counters():
    priv_notes = PrivNotes(password="test")
    title = "note1"
    nonce1 = priv_notes._derive_nonce(title, 1)
    nonce2 = priv_notes._derive_nonce(title, 2)
    assert nonce1 != nonce2


def test_derive_nonce_empty_title():
    priv_notes = PrivNotes(password="test")
    nonce = priv_notes._derive_nonce("", 1)
    assert len(nonce) == 12
