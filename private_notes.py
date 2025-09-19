# internal

# external
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# built-in
import pickle
import os


class PrivNotes:
    MAX_NOTE_LEN = 2048

    def __init__(self, password, data=None, checksum=None):
        """Constructor.

        Args:
          password (str) : password for accessing the notes
          data (str) [Optional] :
            a hex-encoded serialized representation to load
            (defaults to None, which initializes an empty notes database)
          checksum (str) [Optional] :
            a hex-encoded checksum used to protect the data against
            possible rollback attacks (defaults to None, in which
            case, no rollback protection is guaranteed)

        Raises:
          ValueError : malformed serialized format
        """

        salt = None
        if data is not None:
            try:
                raw = bytes.fromhex(data)

                if checksum is not None:
                    digest = hashes.Hash(hashes.SHA256())
                    digest.update(raw)
                    expected = digest.finalize().hex()
                    if checksum != expected:
                        raise ValueError("Checksum verification failed")

                loaded_data = pickle.loads(raw)

                if not (
                    isinstance(loaded_data, dict)
                    and "salt" in loaded_data
                    and "kvs" in loaded_data
                ):
                    raise ValueError("Invalid data format")

                salt = loaded_data["salt"]
                self.kvs = loaded_data["kvs"]

            except Exception as e:
                raise ValueError("Malformed data or tampering detected") from e

        if salt is None:
            salt = os.urandom(16)

        self.salt = salt

        password_bytes = bytes(password, "ascii")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=2000000,
        )

        self.source_key = kdf.derive(password_bytes)

        self.k_title = self._prf(b"TITLE-KEY")
        self.k_enc = self._prf(b"ENC-KEY")
        self.k_nonce = self._prf(b"NONCE-KEY")

        self.aesgcm = AESGCM(self.k_enc)

        if data is None:
            self.kvs = {}

    def dump(self):
        """Computes a serialized representation of the notes database
           together with a checksum.

        Returns:
          data (str) :
            a hex-encoded serialized representation of the contents of
            the notes (that can be passed to the constructor)
          checksum (str) :
            a hex-encoded checksum for the data used to protect
            against rollback attacks (up to 32 characters in length)
        """
        raw = pickle.dumps({"salt": self.salt, "kvs": self.kvs})
        digest = hashes.Hash(hashes.SHA256())
        digest.update(raw)
        checksum = digest.finalize()
        return raw.hex(), checksum.hex()

    def get(self, title: str):
        """Fetches the note associated with a title.

        Args:
          title (str) : the title to fetch

        Returns:
          note (str) : the note associated with the requested title if
                           it exists and otherwise None
        """
        title_key = self._encode_title(self.k_title, title)
        if title_key not in self.kvs:
            return None

        ciphertext, counter = self.kvs[title_key]
        nonce = self._derive_nonce(title, counter)
        return self.decrypt_ciphertext(ciphertext, nonce)

    def set(self, title: str, note: str):
        """Associates a note with a title and adds it to the database
        (or updates the associated note if the title is already
        present in the database).

        Args:
          title (str) : the title to set
          note (str) : the note associated with the title

        Returns:
          None

        Raises:
          ValueError : if note length exceeds the maximum
        """
        if len(note) > self.MAX_NOTE_LEN:
            raise ValueError("Maximum note length exceeded")

        title_key = self._encode_title(self.k_title, title)
        counter = 0
        if title_key in self.kvs:
            _, counter = self.kvs[title_key]
            counter += 1

        nonce = self._derive_nonce(title, counter)

        ciphertext = self.encrypt_plaintext(note, nonce)

        self.kvs[title_key] = (ciphertext, counter)

    def remove(self, title: str):
        title_key = self._encode_title(self.k_title, title)
        if title_key in self.kvs:
            del self.kvs[title_key]
            return True

        return False

    def _prf(self, label: bytes) -> bytes:
        h = hmac.HMAC(self.source_key, hashes.SHA256())
        h.update(label)
        return h.finalize()

    def _encode_title(self, key: bytes, title: str) -> bytes:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(bytes(title, "utf-8"))
        return h.finalize()

    def _pad_fixed(self, message: bytes, max_len: int = 2048) -> bytes:
        if len(message) > max_len:
            raise ValueError("Message too long to pad")

        if len(message) == max_len:
            padded_message = message + b"\x00" * max_len
        else:
            padding_length = max_len - len(message)
            padded_message = message + b"\x00" * padding_length

        return padded_message

    def _unpad_fixed(self, padded: bytes) -> bytes:
        if padded[-1] != 0:
            raise ValueError("Message is not properly padded")
        return padded.rstrip(b"\x00")

    def encrypt_plaintext(self, note: str, nonce: bytes) -> bytes:
        note_bytes: bytes = note.encode("ascii")
        padded: bytes = self._pad_fixed(note_bytes)

        ciphertext: bytes = self.aesgcm.encrypt(nonce, padded, None)

        return ciphertext

    def decrypt_ciphertext(self, ciphertext: bytes, nonce: bytes) -> str:
        padded: bytes = self.aesgcm.decrypt(nonce, ciphertext, None)

        return self._unpad_fixed(padded).decode("ascii")

    def _derive_nonce(self, title: str, counter: int) -> bytes:
        msg = f"{title}:{counter}".encode("utf-8")
        h = hmac.HMAC(self.k_nonce, hashes.SHA256())
        h.update(msg)
        digest = h.finalize()
        return digest[:12]

    def _title_key(self, title: str) -> bytes:
        h = hmac.HMAC(self.k_title, hashes.SHA256())
        h.update(title.encode("ascii"))
        return h.finalize()
