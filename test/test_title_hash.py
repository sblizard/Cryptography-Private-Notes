# internal
from private_notes import PrivNotes

# external

# built-in


def test_title_hash():
    """Test the hashing of titles based on keys and titles."""
    password = "password123"
    title = "My Secret Title"

    # Initialize PrivNotes instance
    notes = PrivNotes(password)

    # Generate a hash for the title
    hashed_title = notes._encode_title(notes.k_title, title)

    # Ensure the hash is not None and has the expected length
    assert hashed_title is not None, "Hashed title should not be None"
    assert len(hashed_title) == 32, "Hashed title should be 32 bytes long"

    # Ensure the hash is consistent for the same title and key
    hashed_title_again = notes._encode_title(notes.k_title, title)
    assert (
        hashed_title == hashed_title_again
    ), "Hash should be consistent for the same title and key"

    # Ensure the hash changes for a different title
    different_title = "Another Title"
    hashed_diff_title = notes._encode_title(notes.k_title, different_title)
    assert hashed_title != hashed_diff_title, "Hash should diff for diff titles"


def test_same_password_different_salt():
    """
    Test that the same password with different salts
    produces different hashes.
    """
    password = "password123"
    title = "My Secret Title"

    # Initialize two PrivNotes instances with the same password
    notes1 = PrivNotes(password)
    notes2 = PrivNotes(password)

    # Generate hashes for the same title
    hashed_title1 = notes1._encode_title(notes1.k_title, title)
    hashed_title2 = notes2._encode_title(notes2.k_title, title)

    # Ensure the hashes are different due to different salts
    assert (
        hashed_title1 != hashed_title2
    ), "Hashes should differ for the same password with different salts"


def test_different_passwords_same_title():
    """
    Test that different passwords produce different
    hashes for the same title.
    """
    password1 = "password123"
    password2 = "differentpassword"
    title = "My Secret Title"

    # Initialize two PrivNotes instances with different passwords
    notes1 = PrivNotes(password1)
    notes2 = PrivNotes(password2)

    # Generate hashes for the same title
    hashed_title1 = notes1._encode_title(notes1.k_title, title)
    hashed_title2 = notes2._encode_title(notes2.k_title, title)

    # Ensure the hashes are different due to different passwords
    assert (
        hashed_title1 != hashed_title2
    ), "Hashes should differ for different passwords"
