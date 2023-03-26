from fernet_gui import *
import time

from cryptography.fernet import InvalidToken


class TimeFernetGui(fernetGui):
    """A class that extends fernetGui and adds time-based encryption and decryption."""

    def __init__(self) -> None:
        super().__init__()

    def encrypt(self, plaintext):
        """Encrypts the plaintext message with a Fernet key.

        Args:
            plaintext (str): The message to encrypt.

        Returns:
            bytes: The encrypted message.
        """
        return self._fernet.encrypt(bytes(plaintext, "utf8"))

    def decrypt(self, data):
        """Decrypts a message with a Fernet key and verifies its time-to-live.

        Args:
            data (bytes): The encrypted message.

        Returns:
            str: The decrypted plaintext message.

        Raises:
            InvalidToken: If the message cannot be decrypted due to an invalid Fernet key or an expired TTL.
        """
        encrypted_data = b64decode(data)    # Decode the base64-encoded message.
        current_time = int(time.time())     # Get the current time to check the TTL.

        try:
            plaintext = self._fernet.decrypt_at_time(encrypted_data, 15, current_time)  # Decrypt the message with time verification.
            return str(plaintext, "utf8")
        except InvalidToken:
            self._log.warning(InvalidToken.__name__)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    client = TimeFernetGui()
    client.create()
    client.loop()
