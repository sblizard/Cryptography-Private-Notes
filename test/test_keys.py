# internal
from private_notes import PrivNotes

# external

# built-in


def test_key_salting():
    pass  # pragma: no cover


def test_prf_unique_keys():
    """Test that the PRF generates unique keys for
    different salts and passwords."""

    password1 = "password123"
    password2 = "differentpassword"

    # Initialize two instances with different passwords
    notes1 = PrivNotes(password1)
    notes2 = PrivNotes(password2)

    # Ensure that the derived keys are different
    assert (
        notes1.k_title != notes2.k_title
    ), "PRF keys should differ for different passwords"
    assert (
        notes1.k_enc != notes2.k_enc
    ), "PRF keys should differ for different passwords"
    assert (
        notes1.k_nonce != notes2.k_nonce
    ), "PRF keys should differ for different passwords"


def test_prf_same_keys():
    """Test that the PRF generates the same keys
    for the same password and salt."""

    password = "password123"

    # Initialize two instances with the same password
    notes1 = PrivNotes(password)
    notes2 = PrivNotes(password, data=notes1.dump()[0])

    # Ensure that the derived keys are the same when loading from same data
    assert (
        notes1.source_key == notes2.source_key
    ), "Source keys should be the same when loading from same data (salt preserved)"
    assert notes1.k_enc == notes2.k_enc, "Encryption keys should be the same"
    assert notes1.k_nonce == notes2.k_nonce, "Nonce keys should be the same"
    assert notes1.k_title == notes2.k_title, "Title keys should be the same"
    assert notes1.k_enc != notes1.k_nonce, "k_enc and k_nonce should be unique"


def test_prf_different_instances():
    """Test that different instances have different keys."""
    
    password = "password123"
    
    # Initialize two separate instances (no data sharing)
    notes1 = PrivNotes(password)
    notes2 = PrivNotes(password)
    
    # Ensure that the derived keys are different due to different salts
    assert (
        notes1.source_key != notes2.source_key
    ), "Source keys should differ due to different salts"
    assert notes1.k_enc != notes2.k_enc, "Encryption keys should be different"
    assert notes1.k_nonce != notes2.k_nonce, "Nonce keys should be different"
    assert notes1.k_title != notes2.k_title, "Title keys should be different"
    assert notes1.k_enc != notes1.k_title, "k_enc and k_title should be unique"
    assert notes1.k_nonce != notes1.k_title, "k_nonce and k_title not unique"
    assert (
        notes1.k_title != notes2.k_title
    ), "PRF keys should differ due to different salts"
