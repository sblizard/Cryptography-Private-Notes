# internal
from private_notes import PrivNotes

# external
import pytest

# built-in


class TestGetSet:
    """Test cases for get and set methods of PrivNotes class."""

    def setup_method(self):
        """Setup for each test method."""
        self.password = "test_password"
        self.notes = PrivNotes(self.password)

    def test_set_and_get_basic(self):
        """Test basic set and get functionality."""
        title = "test_title"
        note = "This is a test note"

        # Set a note
        self.notes.set(title, note)

        # Get the note back
        retrieved_note = self.notes.get(title)

        assert retrieved_note == note

    def test_get_nonexistent_title(self):
        """Test getting a note with a title that doesn't exist."""
        nonexistent_title = "nonexistent"

        result = self.notes.get(nonexistent_title)

        assert result is None

    def test_set_update_existing_title(self):
        """Test updating an existing note with the same title."""
        title = "update_test"
        original_note = "Original note"
        updated_note = "Updated note"

        # Set original note
        self.notes.set(title, original_note)
        assert self.notes.get(title) == original_note

        # Update the note
        self.notes.set(title, updated_note)
        retrieved_note = self.notes.get(title)

        assert retrieved_note == updated_note
        assert retrieved_note != original_note

    def test_set_multiple_notes(self):
        """Test setting and getting multiple different notes."""
        notes_data = {
            "title1": "Note number one",
            "title2": "Note number two",
            "title3": "Note number three",
        }

        # Set all notes
        for title, note in notes_data.items():
            self.notes.set(title, note)

        # Get all notes and verify
        for title, expected_note in notes_data.items():
            retrieved_note = self.notes.get(title)
            assert retrieved_note == expected_note

    def test_set_empty_note(self):
        """Test setting an empty note."""
        title = "empty_note"
        empty_note = ""

        self.notes.set(title, empty_note)
        retrieved_note = self.notes.get(title)

        assert retrieved_note == empty_note

    def test_set_note_with_special_characters(self):
        """Test setting notes with special characters."""
        title = "special_chars"
        note_with_special_chars = "Note with !@#$%^&*()_+-={}[]|;':\",./<>?"

        self.notes.set(title, note_with_special_chars)
        retrieved_note = self.notes.get(title)

        assert retrieved_note == note_with_special_chars

    def test_set_maximum_length_note(self):
        """Test setting a note at the maximum allowed length."""
        title = "max_length"
        max_note = "A" * PrivNotes.MAX_NOTE_LEN

        self.notes.set(title, max_note)
        retrieved_note = self.notes.get(title)

        assert retrieved_note == max_note
        assert (
            retrieved_note is not None and len(retrieved_note) == PrivNotes.MAX_NOTE_LEN
        )

    def test_set_note_exceeds_maximum_length(self):
        """Test that setting a note exceeding maximum length raises ValueError."""
        title = "too_long"
        too_long_note = "A" * (PrivNotes.MAX_NOTE_LEN + 1)

        with pytest.raises(ValueError, match="Maximum note length exceeded"):
            self.notes.set(title, too_long_note)

    def test_title_case_sensitivity(self):
        """Test that titles are case sensitive."""
        note = "Case sensitive test"

        self.notes.set("Title", note)
        self.notes.set("title", note + " lowercase")
        self.notes.set("TITLE", note + " uppercase")

        assert self.notes.get("Title") == note
        assert self.notes.get("title") == note + " lowercase"
        assert self.notes.get("TITLE") == note + " uppercase"

    def test_whitespace_in_titles_and_notes(self):
        """Test handling of whitespace in titles and notes."""
        title_with_spaces = "  title with spaces  "
        note_with_whitespace = "  Note with\n\ttabs and newlines  "

        self.notes.set(title_with_spaces, note_with_whitespace)
        retrieved_note = self.notes.get(title_with_spaces)

        assert retrieved_note == note_with_whitespace
