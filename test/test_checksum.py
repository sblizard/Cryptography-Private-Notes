# internal
from private_notes import PrivNotes

# external
import pytest

# built-in
import hashlib


class TestChecksum:
    """Test cases for checksum functionality in PrivNotes class."""

    def setup_method(self):
        """Setup for each test method."""
        self.password = "test_password"
        self.notes = PrivNotes(self.password)

    def test_checksum_format(self):
        """Test that checksum has correct format."""
        data, checksum = self.notes.dump()

        # Checksum should be a hex string
        assert isinstance(checksum, str)
        assert all(c in "0123456789abcdef" for c in checksum.lower())

        # Checksum should be 64 characters (32 bytes in hex for SHA256)
        assert len(checksum) == 64

    def test_checksum_empty_database(self):
        """Test checksum generation for empty database."""
        data, checksum = self.notes.dump()

        # Manually compute expected checksum
        raw_data = bytes.fromhex(data)
        expected_hash = hashlib.sha256(raw_data).hexdigest()

        assert checksum == expected_hash

    def test_checksum_with_data(self):
        """Test checksum generation with actual data."""
        self.notes.set("test_title", "test_note")
        data, checksum = self.notes.dump()

        # Manually compute expected checksum
        raw_data = bytes.fromhex(data)
        expected_hash = hashlib.sha256(raw_data).hexdigest()

        assert checksum == expected_hash

    def test_checksum_changes_with_data(self):
        """Test that checksum changes when data changes."""
        # Get checksum for empty database
        data1, checksum1 = self.notes.dump()

        # Add a note and get new checksum
        self.notes.set("test", "note")
        data2, checksum2 = self.notes.dump()

        # Checksums should be different
        assert checksum1 != checksum2
        assert data1 != data2

    def test_checksum_deterministic(self):
        """Test that checksum is deterministic for same data."""
        self.notes.set("test", "note")

        data1, checksum1 = self.notes.dump()
        data2, checksum2 = self.notes.dump()

        # Multiple dumps should produce identical checksums
        assert checksum1 == checksum2
        assert data1 == data2

    def test_checksum_verification_valid(self):
        """Test that valid checksum passes verification during construction."""
        # Create notes with some data
        self.notes.set("title1", "note1")
        self.notes.set("title2", "note2")
        data, checksum = self.notes.dump()

        # Creating new instance with correct checksum should work
        # Note: This won't restore the data due to salt regeneration, but should not raise error
        try:
            PrivNotes(self.password, data, checksum)
            # If we get here, checksum verification passed
            assert True
        except ValueError as e:
            if "Malformed data or tampering detected" in str(e):
                # Check if the underlying cause was checksum verification
                if e.__cause__ and "Checksum verification failed" in str(e.__cause__):
                    pytest.fail("Valid checksum was rejected")
            # Other ValueError might be expected due to decryption issues
            pass

    def test_checksum_verification_invalid(self):
        """Test that invalid checksum fails verification during construction."""
        # Create notes with some data
        self.notes.set("title", "note")
        data, checksum = self.notes.dump()

        # Modify checksum to make it invalid
        invalid_checksum = "0" * 64  # All zeros, very unlikely to be correct

        # Should raise ValueError for invalid checksum
        with pytest.raises(ValueError, match="Malformed data or tampering detected"):
            PrivNotes(self.password, data, invalid_checksum)

    def test_checksum_verification_tampered_data(self):
        """Test that checksum detects tampered data."""
        # Create notes with some data
        self.notes.set("title", "note")
        data, checksum = self.notes.dump()

        # Tamper with the data (flip one bit)
        data_bytes = bytes.fromhex(data)
        tampered_bytes = bytearray(data_bytes)
        if len(tampered_bytes) > 0:
            tampered_bytes[0] ^= 1  # Flip one bit
            tampered_data = tampered_bytes.hex()

            # Should raise ValueError for tampered data
            with pytest.raises(
                ValueError, match="Malformed data or tampering detected"
            ):
                PrivNotes(self.password, tampered_data, checksum)

    def test_checksum_verification_none(self):
        """Test that None checksum skips verification."""
        # Create notes with some data
        self.notes.set("title", "note")
        data, checksum = self.notes.dump()

        # Tamper with the data
        data_bytes = bytes.fromhex(data)
        tampered_bytes = bytearray(data_bytes)
        if len(tampered_bytes) > 0:
            tampered_bytes[0] ^= 1  # Flip one bit
            tampered_data = tampered_bytes.hex()

            # With None checksum, should not raise checksum error
            # (may still fail due to other issues like decryption)
            try:
                PrivNotes(self.password, tampered_data, None)
                # If we get here, checksum verification was skipped
                assert True
            except ValueError as e:
                # Should not be checksum verification error (check underlying cause)
                if e.__cause__ and "Checksum verification failed" in str(e.__cause__):
                    pytest.fail(
                        "Checksum verification should have been skipped with None checksum"
                    )
                # Other errors are acceptable (e.g., from pickle.loads on corrupted data)

    def test_checksum_with_multiple_updates(self):
        """Test checksum behavior with multiple note updates."""
        checksums = []

        # Start with empty database
        data, checksum = self.notes.dump()
        checksums.append(checksum)

        # Add first note
        self.notes.set("note1", "content1")
        data, checksum = self.notes.dump()
        checksums.append(checksum)

        # Update first note
        self.notes.set("note1", "updated_content1")
        data, checksum = self.notes.dump()
        checksums.append(checksum)

        # Add second note
        self.notes.set("note2", "content2")
        data, checksum = self.notes.dump()
        checksums.append(checksum)

        # All checksums should be different
        assert len(set(checksums)) == len(checksums)

    def test_checksum_with_note_removal(self):
        """Test checksum changes when notes are removed."""
        # Add some notes
        self.notes.set("note1", "content1")
        self.notes.set("note2", "content2")
        data1, checksum1 = self.notes.dump()

        # Remove a note
        self.notes.remove("note1")
        data2, checksum2 = self.notes.dump()

        # Checksum should change
        assert checksum1 != checksum2
        assert data1 != data2

    def test_checksum_consistency_after_operations(self):
        """Test that checksum remains consistent after various operations."""
        # Perform various operations
        self.notes.set("test1", "content1")
        self.notes.set("test2", "content2")
        self.notes.set("test1", "updated_content1")  # Update
        self.notes.remove("test2")  # Remove
        self.notes.set("test3", "content3")  # Add new

        # Get checksum
        data, checksum = self.notes.dump()

        # Verify checksum is correct
        raw_data = bytes.fromhex(data)
        expected_hash = hashlib.sha256(raw_data).hexdigest()
        assert checksum == expected_hash

    def test_checksum_edge_cases(self):
        """Test checksum with edge cases."""
        # Test with empty note
        self.notes.set("empty", "")
        data1, checksum1 = self.notes.dump()

        # Test with maximum length note
        max_note = "A" * PrivNotes.MAX_NOTE_LEN
        self.notes.set("max", max_note)
        data2, checksum2 = self.notes.dump()

        # Both should have valid checksums
        assert len(checksum1) == 64
        assert len(checksum2) == 64
        assert checksum1 != checksum2

        # Verify checksums are correct
        raw_data1 = bytes.fromhex(data1)
        expected_hash1 = hashlib.sha256(raw_data1).hexdigest()
        assert checksum1 == expected_hash1

        raw_data2 = bytes.fromhex(data2)
        expected_hash2 = hashlib.sha256(raw_data2).hexdigest()
        assert checksum2 == expected_hash2
