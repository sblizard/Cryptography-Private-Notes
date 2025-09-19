# internal
from private_notes import PrivNotes

# external

# built-in
import pickle


class TestDump:
    """Test cases for dump method of PrivNotes class."""

    def setup_method(self):
        """Setup for each test method."""
        self.password = "test_password"
        self.notes = PrivNotes(self.password)

    def test_dump_empty_database(self):
        """Test dumping an empty notes database."""
        data, checksum = self.notes.dump()

        # Data should be a hex string
        assert isinstance(data, str)
        assert all(c in "0123456789abcdef" for c in data.lower())

        # Checksum should be a hex string
        assert isinstance(checksum, str)
        assert all(c in "0123456789abcdef" for c in checksum.lower())

        # Checksum should be 64 characters (32 bytes in hex)
        assert len(checksum) == 64

        # Data should represent an empty dictionary when decoded
        decoded_data = pickle.loads(bytes.fromhex(data))
        assert decoded_data == {}

    def test_dump_single_note(self):
        """Test dumping database with a single note."""
        title = "test_title"
        note = "test_note"

        self.notes.set(title, note)
        data, checksum = self.notes.dump()

        # Verify data format
        assert isinstance(data, str)
        assert all(c in "0123456789abcdef" for c in data.lower())

        # Verify checksum format
        assert isinstance(checksum, str)
        assert len(checksum) == 64

        # Verify data can be decoded and contains our note
        decoded_data = pickle.loads(bytes.fromhex(data))
        assert len(decoded_data) == 1

        # Note: Cannot test reconstruction due to salt regeneration in constructor

    def test_dump_multiple_notes(self):
        """Test dumping database with multiple notes."""
        notes_data = {
            "title1": "Note one",
            "title2": "Note two",
            "title3": "Note three",
        }

        # Add all notes
        for title, note in notes_data.items():
            self.notes.set(title, note)

        data, checksum = self.notes.dump()

        # Verify format
        assert isinstance(data, str)
        assert isinstance(checksum, str)
        assert len(checksum) == 64

        # Verify data contains all notes
        decoded_data = pickle.loads(bytes.fromhex(data))
        assert len(decoded_data) == len(notes_data)

        # Note: Cannot test reconstruction due to salt regeneration in constructor

    def test_dump_after_update(self):
        """Test that dump reflects updates to existing notes."""
        title = "update_test"
        original_note = "original"
        updated_note = "updated"

        # Set original note and dump
        self.notes.set(title, original_note)
        data1, checksum1 = self.notes.dump()

        # Update note and dump again
        self.notes.set(title, updated_note)
        data2, checksum2 = self.notes.dump()

        # Data and checksum should be different
        assert data1 != data2
        assert checksum1 != checksum2

        # Verify the current instance still has the updated note
        assert self.notes.get(title) == updated_note

    def test_dump_deterministic_for_same_data(self):
        """Test that dump produces consistent results for the same data."""
        title = "consistency_test"
        note = "consistent_note"

        self.notes.set(title, note)
        data1, checksum1 = self.notes.dump()
        data2, checksum2 = self.notes.dump()

        # Multiple calls to dump should produce identical results
        assert data1 == data2
        assert checksum1 == checksum2

    def test_dump_with_large_note(self):
        """Test dumping with a note at maximum size."""
        title = "large_note"
        large_note = "A" * PrivNotes.MAX_NOTE_LEN

        self.notes.set(title, large_note)
        data, checksum = self.notes.dump()

        # Verify format
        assert isinstance(data, str)
        assert isinstance(checksum, str)
        assert len(checksum) == 64

        # Verify the note was stored (can't test reconstruction due to salt issue)
        assert self.notes.get(title) == large_note

    def test_dump_with_special_characters(self):
        """Test dumping notes with ASCII special characters."""
        title = "special_chars"
        # Only ASCII special characters since the implementation uses ASCII encoding
        note = "Special chars: !@#$%^&*()_+-={}[]|;':\",./<>?"

        self.notes.set(title, note)
        data, checksum = self.notes.dump()

        # Verify format
        assert isinstance(data, str)
        assert isinstance(checksum, str)
        assert len(checksum) == 64

        # Verify the note was stored correctly
        assert self.notes.get(title) == note

    def test_dump_with_ascii_only(self):
        """Test dumping notes with ASCII characters only (since implementation uses ASCII encoding)."""
        title = "ascii_test"
        note = "ASCII only: Hello World 123"

        self.notes.set(title, note)
        data, checksum = self.notes.dump()

        # Verify format
        assert isinstance(data, str)
        assert isinstance(checksum, str)
        assert len(checksum) == 64

        # Verify the note was stored correctly
        assert self.notes.get(title) == note

    def test_dump_empty_string_note(self):
        """Test dumping with an empty string note."""
        title = "empty_note"
        note = ""

        self.notes.set(title, note)
        data, checksum = self.notes.dump()

        # Verify format
        assert isinstance(data, str)
        assert isinstance(checksum, str)
        assert len(checksum) == 64

        # Verify the empty note was stored correctly
        assert self.notes.get(title) == note

    def test_dump_checksum_integrity(self):
        """Test that checksum changes when data is modified."""
        title1 = "note1"
        title2 = "note2"
        note = "test note"

        # Dump with one note
        self.notes.set(title1, note)
        data1, checksum1 = self.notes.dump()

        # Add another note
        self.notes.set(title2, note)
        data2, checksum2 = self.notes.dump()

        # Checksums should be different
        assert checksum1 != checksum2
        assert data1 != data2

    def test_dump_data_isolation(self):
        """Test that dump data reflects current state correctly."""
        original_title = "original"
        original_note = "original note"
        new_title = "new"
        new_note = "new note"

        # Set note in original and dump
        self.notes.set(original_title, original_note)
        data, checksum = self.notes.dump()

        # Verify data represents current state
        decoded_data = pickle.loads(bytes.fromhex(data))
        assert len(decoded_data) == 1

        # Modify original instance
        self.notes.set(new_title, new_note)
        data2, checksum2 = self.notes.dump()

        # New dump should be different
        assert data != data2
        assert checksum != checksum2

        # New dump should have both notes
        decoded_data2 = pickle.loads(bytes.fromhex(data2))
        assert len(decoded_data2) == 2

        # Original instance should have both notes
        assert self.notes.get(original_title) == original_note
        assert self.notes.get(new_title) == new_note
