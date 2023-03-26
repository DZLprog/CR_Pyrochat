from cryptography.fernet import Fernet
from Ciphered_gui import *
from base64 import b64encode, b64decode

from hashlib import sha256


class fernetGui(CipheredGUI):
    
    def __init__(self) -> None:
        super().__init__()
        self._fernet = None

    def encrypt(self, plaintext):
        #Encrypts plaintext with Fernet encryption algorithm.

        #Args: plaintext (str): The string message to be encrypted.

        #Returns: bytes: The encrypted message in bytes.

        cipher = self._fernet.encrypt(bytes(plaintext, "utf8"))
        return cipher
    
    def decrypt(self, data):
        #Decrypts Fernet encrypted data.

        #Args: data (bytes): The encrypted data in bytes.

        #Returns: str: The decrypted message in string format.
        encrypted_data = b64decode(data)                 # Decode base64 encrypted data
        plaintext = self._fernet.decrypt(encrypted_data) # Decrypt message
        return str(plaintext, "utf8")


    def run_chat(self, sender, app_data) -> None:
        #Overrides CipheredGUI method.
        #Runs the chat application, sets up the encryption key with user input password.

        #Args:sender (int): Sender ID /app_data (Any): Application data
        
        super().run_chat(sender, app_data)

        passwd = dpg.get_value("connection_password")   # Get password from user input

        m = sha256()                                    # Initialize sha256 object
        m.update(bytes(passwd, "utf8"))                 # Update sha256 object with password
        key = m.digest()                                # Hash the password using SHA256 to obtain key
        self._key = b64encode(key)                      # Encode the key in base64
        self._fernet = Fernet(self._key)  
        
        
        

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    
    client = fernetGui()
    client.create()
    client.loop()
