# internal
from private_notes import PrivNotes

# external
import pytest

# built-in
import pickle
import hashlib
import os


class TestPrivNotesIntegration:
    """Comprehensive integration tests covering the entire PrivNotes flow."""

    def setup_method(self):
        """Setup for each test method."""
        self.password = "test_password_123"
        self.alt_password = "different_password"

    def test_complete_new_instance_flow(self):
        """Test complete flow: create new instance -> add notes -> retrieve notes."""
        # Step 1: Create new instance
        notes = PrivNotes(self.password)

        # Verify initial state
        assert notes.kvs == {}
        assert isinstance(notes.salt, bytes)
        assert len(notes.salt) == 16
        assert isinstance(notes.source_key, bytes)
        assert len(notes.source_key) == 32

        # Step 2: Add single note
        title1 = "test_title"
        note1 = "test_note_content"
        notes.set(title1, note1)

        # Verify note was added
        assert len(notes.kvs) == 1
        retrieved = notes.get(title1)
        assert retrieved == note1

        # Step 3: Add multiple notes
        test_data = {
            "Shopping": "milk, bread, eggs",
            "Ideas": "Learn cryptography",
            "Passwords": "secret123",
            "Empty": "",
            "Long": "A" * 1000,  # Test with long content
        }

        for title, note in test_data.items():
            notes.set(title, note)

        # Verify all notes
        assert len(notes.kvs) == 6  # original + 5 new
        for title, expected_note in test_data.items():
            retrieved = notes.get(title)
            assert retrieved == expected_note

        # Verify original note still exists
        assert notes.get(title1) == note1

    def test_complete_dump_load_flow(self):
        """Test complete flow: create -> populate -> dump -> load -> verify."""
        # Step 1: Create and populate original instance
        original_notes = PrivNotes(self.password)

        test_data = {
            "Note1": "Content for note 1",
            "Note2": "Content for note 2 with special chars !@#$%",
            "Note3": "",
            "Note4": "Very long note: " + "X" * 1500,
        }

        for title, note in test_data.items():
            original_notes.set(title, note)

        # Step 2: Dump the data
        data, checksum = original_notes.dump()

        # Verify dump format
        assert isinstance(data, str)
        assert isinstance(checksum, str)
        assert len(checksum) == 64
        assert all(c in "0123456789abcdef" for c in data.lower())
        assert all(c in "0123456789abcdef" for c in checksum.lower())

        # Verify checksum is correct
        raw_data = bytes.fromhex(data)
        expected_checksum = hashlib.sha256(raw_data).hexdigest()
        assert checksum == expected_checksum

        # Verify serialized data contains salt and kvs
        loaded_raw = pickle.loads(raw_data)
        assert isinstance(loaded_raw, dict)
        assert "salt" in loaded_raw
        assert "kvs" in loaded_raw
        assert loaded_raw["salt"] == original_notes.salt
        assert loaded_raw["kvs"] == original_notes.kvs

        # Step 3: Load into new instance
        loaded_notes = PrivNotes(self.password, data, checksum)

        # Verify loaded instance has same salt and keys
        assert loaded_notes.salt == original_notes.salt
        assert loaded_notes.source_key == original_notes.source_key
        assert loaded_notes.k_title == original_notes.k_title
        assert loaded_notes.k_enc == original_notes.k_enc
        assert loaded_notes.k_nonce == original_notes.k_nonce

        # Step 4: Verify all data is accessible
        for title, expected_note in test_data.items():
            retrieved = loaded_notes.get(title)
            assert retrieved == expected_note, f"Failed for title '{title}'"

        # Step 5: Verify both instances behave identically
        for title in test_data:
            original_result = original_notes.get(title)
            loaded_result = loaded_notes.get(title)
            assert original_result == loaded_result

    def test_update_operations_flow(self):
        """Test complete flow with updates: create -> add -> update -> verify."""
        notes = PrivNotes(self.password)

        # Step 1: Add initial notes
        initial_data = {
            "Note1": "Initial content 1",
            "Note2": "Initial content 2",
            "Note3": "Initial content 3",
        }

        for title, note in initial_data.items():
            notes.set(title, note)

        # Verify initial state
        for title, expected in initial_data.items():
            assert notes.get(title) == expected

        # Step 2: Update existing notes
        updated_data = {
            "Note1": "Updated content 1",
            "Note2": "Completely different content",
            "Note3": "",  # Update to empty
        }

        for title, note in updated_data.items():
            notes.set(title, note)

        # Step 3: Verify updates
        for title, expected in updated_data.items():
            retrieved = notes.get(title)
            assert retrieved == expected

        # Step 4: Verify counter incrementation
        # Each update should increment the counter
        for title_key, (ciphertext, counter) in notes.kvs.items():
            assert counter >= 1  # Should be at least 1 after update

        # Step 5: Dump and reload to verify persistence
        data, checksum = notes.dump()
        reloaded_notes = PrivNotes(self.password, data, checksum)

        for title, expected in updated_data.items():
            assert reloaded_notes.get(title) == expected

    def test_remove_operations_flow(self):
        """Test complete flow with removals: create -> add -> remove -> verify."""
        notes = PrivNotes(self.password)

        # Step 1: Add multiple notes
        test_data = {
            "Keep1": "Keep this note",
            "Remove1": "Remove this note",
            "Keep2": "Keep this too",
            "Remove2": "Remove this too",
            "Keep3": "Final keeper",
        }

        for title, note in test_data.items():
            notes.set(title, note)

        # Verify all added
        assert len(notes.kvs) == 5
        for title, expected in test_data.items():
            assert notes.get(title) == expected

        # Step 2: Remove some notes
        to_remove = ["Remove1", "Remove2"]
        to_keep = ["Keep1", "Keep2", "Keep3"]

        for title in to_remove:
            result = notes.remove(title)
            assert result is True

        # Step 3: Verify removals
        assert len(notes.kvs) == 3

        for title in to_remove:
            assert notes.get(title) is None

        for title in to_keep:
            assert notes.get(title) == test_data[title]

        # Step 4: Try to remove non-existent note
        result = notes.remove("NonExistent")
        assert result is False

        # Step 5: Dump and reload to verify persistence
        data, checksum = notes.dump()
        reloaded_notes = PrivNotes(self.password, data, checksum)

        assert len(reloaded_notes.kvs) == 3
        for title in to_remove:
            assert reloaded_notes.get(title) is None
        for title in to_keep:
            assert reloaded_notes.get(title) == test_data[title]

    def test_security_scenarios_flow(self):
        """Test security-related scenarios: wrong passwords, tampering, etc."""
        notes = PrivNotes(self.password)

        # Add some data
        notes.set("Secret", "confidential information")
        data, checksum = notes.dump()

        # Test 1: Wrong password - create more comprehensive test
        wrong_password_notes = PrivNotes(self.alt_password, data, checksum)
        
        # Method 1: The title hashing will be different, so get() returns None
        assert wrong_password_notes.get("Secret") is None
        
        # Method 2: Test direct decryption failure with wrong keys
        # Get the ciphertext from the loaded kvs and try to decrypt with wrong-derived keys
        if wrong_password_notes.kvs:
            first_key = list(wrong_password_notes.kvs.keys())[0]
            ciphertext, counter = wrong_password_notes.kvs[first_key]
            # Try to decrypt with wrong-derived nonce (this should fail)
            with pytest.raises(Exception):  # InvalidTag or similar crypto error
                nonce = wrong_password_notes._derive_nonce("Secret", counter)
                wrong_password_notes.decrypt_ciphertext(ciphertext, nonce)

        # Test 2: Tampered data
        data_bytes = bytes.fromhex(data)
        tampered_bytes = bytearray(data_bytes)
        tampered_bytes[10] ^= 1  # Flip one bit
        tampered_data = tampered_bytes.hex()

        with pytest.raises(ValueError, match="Malformed data or tampering detected"):
            PrivNotes(self.password, tampered_data, checksum)

        # Test 3: Wrong checksum
        wrong_checksum = "0" * 64
        with pytest.raises(ValueError, match="Malformed data or tampering detected"):
            PrivNotes(self.password, data, wrong_checksum)

        # Test 4: Valid password and data should work
        valid_notes = PrivNotes(self.password, data, checksum)
        assert valid_notes.get("Secret") == "confidential information"

    def test_edge_cases_flow(self):
        """Test edge cases and boundary conditions."""
        notes = PrivNotes(self.password)

        # Test 1: Empty strings
        notes.set("Empty", "")
        assert notes.get("Empty") == ""

        # Test 2: Maximum length note
        max_note = "X" * PrivNotes.MAX_NOTE_LEN
        notes.set("MaxNote", max_note)
        assert notes.get("MaxNote") == max_note

        # Test 3: Note too long
        too_long = "X" * (PrivNotes.MAX_NOTE_LEN + 1)
        with pytest.raises(ValueError, match="Maximum note length exceeded"):
            notes.set("TooLong", too_long)

        # Test 4: Special characters in titles and notes
        special_chars = "!@#$%^&*()_+-={}[]|;':\",./<>?"
        notes.set(special_chars, special_chars)
        assert notes.get(special_chars) == special_chars

        # Test 5: Unicode in titles (UTF-8 encoding)
        unicode_title = "título_ñ"
        unicode_note = "content"  # Note: content must be ASCII due to implementation
        notes.set(unicode_title, unicode_note)
        assert notes.get(unicode_title) == unicode_note

        # Test 6: Dump and reload with edge cases
        data, checksum = notes.dump()
        reloaded = PrivNotes(self.password, data, checksum)

        assert reloaded.get("Empty") == ""
        assert reloaded.get("MaxNote") == max_note
        assert reloaded.get(special_chars) == special_chars
        assert reloaded.get(unicode_title) == unicode_note

    def test_multiple_instances_independence(self):
        """Test that multiple instances are independent."""
        # Create two independent instances
        notes1 = PrivNotes(self.password)
        notes2 = PrivNotes(self.password)

        # Verify they have different salts
        assert notes1.salt != notes2.salt
        assert notes1.source_key != notes2.source_key

        # Add different data to each
        notes1.set("Note1", "Content for instance 1")
        notes2.set("Note2", "Content for instance 2")

        # Verify independence
        assert notes1.get("Note1") == "Content for instance 1"
        assert notes1.get("Note2") is None
        assert notes2.get("Note2") == "Content for instance 2"
        assert notes2.get("Note1") is None

        # Dump and cross-load (should fail)
        data1, checksum1 = notes1.dump()
        data2, checksum2 = notes2.dump()

        # Instance 2 data can't be loaded with instance 1's password/salt relationship
        cross_loaded = PrivNotes(self.password, data2, checksum2)
        # This will load but won't be able to decrypt notes1's data
        assert cross_loaded.get("Note1") is None
        assert cross_loaded.get("Note2") == "Content for instance 2"

    def test_counter_behavior_flow(self):
        """Test that counters work correctly for replay protection."""
        notes = PrivNotes(self.password)

        title = "CounterTest"

        # Set initial note
        notes.set(title, "Version 1")

        # Check internal counter
        title_key = notes._encode_title(notes.k_title, title)
        ciphertext1, counter1 = notes.kvs[title_key]
        assert counter1 == 0

        # Update note multiple times
        for i in range(2, 6):
            notes.set(title, f"Version {i}")
            ciphertext, counter = notes.kvs[title_key]
            assert counter == i - 1
            assert notes.get(title) == f"Version {i}"

        # Dump and reload
        data, checksum = notes.dump()
        reloaded = PrivNotes(self.password, data, checksum)

        # Verify counter persisted
        title_key_reloaded = reloaded._encode_title(reloaded.k_title, title)
        ciphertext_reloaded, counter_reloaded = reloaded.kvs[title_key_reloaded]
        assert counter_reloaded == 4  # Last counter value
        assert reloaded.get(title) == "Version 5"

        # Continue updating in reloaded instance
        reloaded.set(title, "Version 6")
        ciphertext_new, counter_new = reloaded.kvs[title_key_reloaded]
        assert counter_new == 5

    def test_nonce_derivation_flow(self):
        """Test nonce derivation for different scenarios."""
        notes = PrivNotes(self.password)

        # Test 1: Same title, different counters produce different nonces
        title = "TestTitle"
        nonce1 = notes._derive_nonce(title, 0)
        nonce2 = notes._derive_nonce(title, 1)
        nonce3 = notes._derive_nonce(title, 2)

        assert len(nonce1) == 12
        assert len(nonce2) == 12
        assert len(nonce3) == 12
        assert nonce1 != nonce2 != nonce3

        # Test 2: Different titles, same counter produce different nonces
        nonce_a = notes._derive_nonce("TitleA", 0)
        nonce_b = notes._derive_nonce("TitleB", 0)

        assert nonce_a != nonce_b

        # Test 3: Nonce derivation is deterministic
        nonce_repeat = notes._derive_nonce(title, 0)
        assert nonce1 == nonce_repeat

    def test_encryption_decryption_flow(self):
        """Test encryption/decryption with various data."""
        notes = PrivNotes(self.password)

        test_cases = [
            "",
            "a",
            "Hello World",
            "Special chars: !@#$%^&*()",
            "Numbers: 1234567890",
            "A" * 100,
            "A" * PrivNotes.MAX_NOTE_LEN,
        ]

        for i, test_note in enumerate(test_cases):
            title = f"Test{i}"

            # Set and get
            notes.set(title, test_note)
            retrieved = notes.get(title)
            assert retrieved == test_note

            # Verify encryption/decryption internals
            title_key = notes._encode_title(notes.k_title, title)
            ciphertext, counter = notes.kvs[title_key]
            nonce = notes._derive_nonce(title, counter)

            # Decrypt manually
            decrypted = notes.decrypt_ciphertext(ciphertext, nonce)
            assert decrypted == test_note

    def test_malformed_data_scenarios(self):
        """Test various malformed data scenarios."""
        # Test 1: Invalid hex data
        with pytest.raises(ValueError, match="Malformed data or tampering detected"):
            PrivNotes(self.password, "invalid_hex", None)

        # Test 2: Valid hex but invalid pickle data
        invalid_pickle = "deadbeef"
        with pytest.raises(ValueError, match="Malformed data or tampering detected"):
            PrivNotes(self.password, invalid_pickle, None)

        # Test 3: Valid pickle but wrong format
        wrong_format = pickle.dumps({"wrong": "format"}).hex()
        with pytest.raises(ValueError, match="Malformed data or tampering detected"):
            PrivNotes(self.password, wrong_format, None)

        # Test 4: Missing salt or kvs
        missing_salt = pickle.dumps({"kvs": {}}).hex()
        with pytest.raises(ValueError, match="Malformed data or tampering detected"):
            PrivNotes(self.password, missing_salt, None)

        missing_kvs = pickle.dumps({"salt": os.urandom(16)}).hex()
        with pytest.raises(ValueError, match="Malformed data or tampering detected"):
            PrivNotes(self.password, missing_kvs, None)

    def test_complete_lifecycle_scenario(self):
        """Test a complete realistic usage scenario."""
        # Day 1: Create new notes database
        notes = PrivNotes("my_secure_password")

        # Add initial notes
        notes.set("Grocery List", "milk, bread, eggs, cheese")
        notes.set("Meeting Notes", "Discuss project timeline")
        notes.set("Passwords", "github: mysecret123")

        # Save to storage
        day1_data, day1_checksum = notes.dump()

        # Day 2: Load from storage
        notes_day2 = PrivNotes("my_secure_password", day1_data, day1_checksum)

        # Verify data is accessible
        assert notes_day2.get("Grocery List") == "milk, bread, eggs, cheese"
        assert notes_day2.get("Meeting Notes") == "Discuss project timeline"
        assert notes_day2.get("Passwords") == "github: mysecret123"

        # Update existing and add new
        notes_day2.set("Grocery List", "milk, bread, eggs, cheese, apples")
        notes_day2.set("TODO", "Finish project documentation")
        notes_day2.remove("Meeting Notes")  # No longer needed

        # Save updated state
        day2_data, day2_checksum = notes_day2.dump()

        # Day 3: Load and verify
        notes_day3 = PrivNotes("my_secure_password", day2_data, day2_checksum)

        assert notes_day3.get("Grocery List") == "milk, bread, eggs, cheese, apples"
        assert notes_day3.get("Meeting Notes") is None
        assert notes_day3.get("Passwords") == "github: mysecret123"
        assert notes_day3.get("TODO") == "Finish project documentation"

        # Verify checksums changed appropriately
        assert day1_checksum != day2_checksum  # Data changed between days

        # Verify data integrity
        final_data, final_checksum = notes_day3.dump()
        verification_notes = PrivNotes("my_secure_password", final_data, final_checksum)

        assert verification_notes.get("Grocery List") == notes_day3.get("Grocery List")
        assert verification_notes.get("Passwords") == notes_day3.get("Passwords")
        assert verification_notes.get("TODO") == notes_day3.get("TODO")
        assert verification_notes.get("Meeting Notes") is None
