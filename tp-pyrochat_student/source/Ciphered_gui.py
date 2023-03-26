import logging

import dearpygui.dearpygui as dpg

import os

from chat_client import ChatClient
from generic_callback import GenericCallback
from basic_gui import BasicGUI,DEFAULT_VALUES
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
import serpent

DEFAULT_VALUES["pass"] = "pass"
salt = b"pyrochattest"

# Configuration du kdf
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=16, #nombre d'octet
    salt=salt,
    iterations=100000, #itérations AES
)

# Import AES 
#j'importe tous les biblio neccessaire au cas ou
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


import base64

# Surcharger avec self
class CipheredGUI(BasicGUI):
    def __init__(self) -> None:
        super().__init__()
        self.key = None

    #inclure un champ password
    def _create_connection_window(self) -> None:
        with dpg.window(label="Connection", pos=(200, 150), width=400, height=300, show=False, tag="connection_windows"):

            for field in ["host", "port", "name"]:
                with dpg.group(horizontal=True):
                    dpg.add_text(field)
                    dpg.add_input_text(
                        default_value=DEFAULT_VALUES[field], tag=f"connection_{field}")
            with dpg.group(horizontal=True):
                dpg.add_text("User Password")
                dpg.add_input_text(default_value="", tag=f"connection_password", password=True)
            dpg.add_button(label="Connect", callback=self.run_chat)


    #récupération du mot de passe
    def run_chat(self, sender, app_data) -> None:
        host = dpg.get_value("connection_host")
        port = int(dpg.get_value("connection_port"))
        name = dpg.get_value("connection_name")
        password = dpg.get_value("connection_password")
        self._log.info(f"Connecting {name}@{host}:{port}")

        self._callback = GenericCallback()

        self._client = ChatClient(host, port)
        self._client.start(self._callback)
        self._client.register(name)

        dpg.hide_item("connection_windows")
        dpg.show_item("chat_windows")
        dpg.set_value("screen", "Connecting")
        passwd = dpg.get_value("connection_password")
        self.key = self._key = kdf.derive(bytes(passwd, "utf8")) 

    def encrypt(self, plaintext):
        # Generate a random 16-byte initialization vector (IV)
        iv  = os.urandom(16)      
        # Create a Cipher object using AES encryption in CTR mode with the generated IV and the key self._key                                  
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv))  
        # Create an encryptor object to encrypt the plaintext
        encryptor = cipher.encryptor()                              

        # Pad the plaintext using PKCS7 padding
        padder = padding.PKCS7(128).padder()                        # Ajout d'un padding pour obtenir la taille souhaitée.
        padded_text = padder.update(bytes(plaintext, "utf8")) + padder.finalize()

        # Encrypt the padded plaintext and get the ciphertext
        ct = encryptor.update(padded_text) + encryptor.finalize()   # Cipher final à envoyer

        # Return a tuple containing the IV and the ciphertext
        return (iv, ct)


    def decrypt(self, data):

        # Get the initialization vector (IV) and the encrypted text from the input tuple
        iv = data[0]                                                
        encrypted = data[1]                                         

        # Create a Cipher object using AES encryption in CTR mode with the retrieved IV and the key self._key
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv))   
        # Create a decryptor object to decrypt the ciphertext
        decryptor = cipher.decryptor()                              

        # Decrypt the ciphertext and get the padded plaintext
        padded_text = decryptor.update(encrypted) + decryptor.finalize()

        # Create an unpadder object to remove the PKCS7 padding from the padded plaintext
        unpadder = padding.PKCS7(128).unpadder()                    # Création de l'objet unpadder

        # Remove the padding and get the plaintext as bytes
        plaintext = unpadder.update(padded_text) + unpadder.finalize()

        # Convert the plaintext bytes to a string and return it
        return str(plaintext, "utf8")

    #fonction d'envoyer les messages
    def send(self, text) -> None:
        message = self.encrypt(text)
        self._client.send_message(message)


    #fonction de réception des messages
    def recv(self) -> None:
        if self._callback is not None:
            for user, message in self._callback.get():
                 #essai de déchiffrer le message
                try:
                    #Déchiffrer le message
                    message = self.decrypt(message)
                    #Afficher le message déchiffré
                    self.update_text_screen(f"{user} : {message.decode()}")
                except:
                    #Afficher le message chiffré dans les logs
                    self._log.error(f"Decrypting error: {message}")
            self._callback.clear()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    client = CipheredGUI()
    client.create()
    client.loop()
