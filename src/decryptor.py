from PyQt6.QtCore import QSize, Qt
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea, QPlainTextEdit, QPushButton, QMessageBox
from PyQt6.QtGui import QColor, QPalette

import shamirs
import json
import itertools
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

PROJECT_NAME = '[projectname]'
# BG_COLOUR = QColor('black')
# TEXT_COLOUR = QColor('green')
PRIME_MODULUS = 9531*2**9531-1 # 2874-digit prime, larger than 256**1024 # (previously: 4122429552750669*2**16567+1 # 5003-digit prime, larger than 256**2048)

# obviously update this later
with open("data/private_key.pem", "rb") as key_file:
    PRIVATE_KEY = serialization.load_pem_private_key(key_file.read(), password=None)
with open("data/public_key.pem", "rb") as key_file:
    PUBLIC_KEY = serialization.load_pem_public_key(key_file.read())

shamirs.share.__eq__ = lambda self, other: self.index == other.index and self.value == other.value and self.modulus == other.modulus

# Subclass QMainWindow to customize your application's main window
class DecryptorMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.keys = {} # key: keybox
        self.secrets = {} # secret: secretbox

        self.setWindowTitle(f'{PROJECT_NAME} decryptor')
        top_layout = QVBoxLayout()
        self.secrets_layout = QHBoxLayout()
        secrets_widget = Colour('red')
        secrets_widget.setLayout(self.secrets_layout)
        secrets_scroll_widget = QScrollArea()
        secrets_scroll_widget.setWidget(secrets_widget)
        secrets_scroll_widget.setWidgetResizable(True)
        top_layout.addWidget(secrets_scroll_widget)
        self.keys_layout = QHBoxLayout()
        self.keys_layout.addWidget(AddKeyBox())
        keys_widget = Colour('blue')
        keys_widget.setLayout(self.keys_layout)
        keys_scroll_widget = QScrollArea()
        keys_scroll_widget.setWidget(keys_widget)
        keys_scroll_widget.setWidgetResizable(True)
        top_layout.addWidget(keys_scroll_widget)
        
        central_widget = QWidget()
        central_widget.setLayout(top_layout)
        # Set the central widget of the Window.
        self.setCentralWidget(central_widget)

    def addSecret(self, secret_int):
        try:
            secret_json = json.loads(int_to_string(secret_int))
            secret = secret_json['secret']
            sig = base64.b64decode(secret_json['signature'])
        except Exception as e:
            print(e) # invalid formatting
            return
        try:
            PUBLIC_KEY.verify(sig, secret.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        except InvalidSignature:
            self.messageBox("found a secret, but it doesn't have a valid {PROJECT_NAME} signature - the data may be tampered with or corrupted", 'signature warning')
        new_secret_box = SecretBox(secret)
        self.secrets_layout.addWidget(new_secret_box)
        self.secrets[secret] = new_secret_box

    def addKey(self, key_string):
        try:
            key_data = json.loads(base64.b64decode(key_string).decode('utf-8'))
            key = shamirs.share(index = key_data['index'],
                                value = base64_to_int(key_data['value']),
                                modulus = PRIME_MODULUS)
        except Exception as e:
            self.messageBox(f'not a valid {PROJECT_NAME} key', 'invalid key')
            return False

        for other_key in self.keys:
            if other_key == key:
                self.messageBox('you already have that key', 'key already present')
                return False
        
        self.checkForSecrets(key)
        new_key_box = KeyBox(key)
        self.keys_layout.insertWidget(self.keys_layout.count()-1, new_key_box)
        self.keys[key] = new_key_box

        return True

    def removeKey(self, key):
        self.keys_layout.removeWidget(self.keys[key])
        self.keys[key].deleteLater()
        self.keys.pop(key)
        # TODO: remove any secret that depended on it

    def removeSecret(self, secret):
        self.secrets_layout.removeWidget(self.secrets[secret])
        self.secrets[secret].deleteLater()
        self.secrets.pop(secret)

    def checkForSecrets(self, new_key):
        for quantity in range(len(self.keys)+1):
            for combo in itertools.combinations(self.keys, quantity):
                try:
                    new_secret = shamirs.interpolate(list(combo) + [new_key])
                    self.addSecret(new_secret)
                except Exception as e:
                    print(e)
                    pass

    def messageBox(self, message, title):
        dlg = QMessageBox(self)
        dlg.setWindowTitle(title)
        dlg.setText(message)
        dlg.exec()
            

class SecretBox(QWidget):
    def __init__(self, secret):
        super().__init__()
        self.setAutoFillBackground(True)
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor('black'))
        self.setPalette(palette)
        layout = QVBoxLayout()
        layout.addWidget(QLabel(str(secret)))
        self.setLayout(layout)

class KeyBox(QWidget):
    def __init__(self, key):
        super().__init__()
        self.key = key
        self.setAutoFillBackground(True)
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor('black'))
        self.setPalette(palette)
        x_button = QPushButton('X')
        x_button.setCheckable(True)
        x_button.clicked.connect(self.delete)
        layout = QVBoxLayout()
        layout.addWidget(x_button)
        layout.addWidget(QLabel(str(key)))
        self.setLayout(layout)
    def delete(self):
        self.parent().parent().parent().parent().parent().removeKey(self.key)

class AddKeyBox(QWidget):
    def __init__(self):
        super().__init__()
        self.setAutoFillBackground(True)
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor('black'))
        self.setPalette(palette)
        add_button = QPushButton('+')
        add_button.setCheckable(True)
        add_button.clicked.connect(self.add_button_pressed)
        self.text_box = QPlainTextEdit()
        layout = QVBoxLayout()
        layout.addWidget(self.text_box)
        layout.addWidget(add_button)
        self.setLayout(layout)
    def add_button_pressed(self):
        if self.parent().parent().parent().parent().parent().addKey(self.text_box.toPlainText()):
            self.text_box.clear()

class Colour(QWidget):
    def __init__(self, color):
        super().__init__()
        self.setMinimumSize(QSize(10,10))
        self.setAutoFillBackground(True)
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor(color))
        self.setPalette(palette)

def string_to_int(string):
    return int.from_bytes(string.encode('utf-8'), 'little')

def int_to_string(integer):
    return integer.to_bytes((integer.bit_length() + 7) // 8, 'little').decode('utf-8')

def int_to_base64(integer):
    return base64.b64encode(integer.to_bytes((integer.bit_length()+7)//8,'little')).decode('utf-8')

def base64_to_int(b64str):
    return int.from_bytes(base64.b64decode(b64str), 'little')

def make_json_shares(value):
    sig = base64.b64encode(PRIVATE_KEY.sign(value.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())).decode('utf-8')
    shares = shamirs.shares(string_to_int(f'{{"secret": "{value}", "signature": "{sig}"}}'), quantity = 2, modulus = PRIME_MODULUS)
    print(f'{{"secret": "{value}", "signature": "{sig}"}}')
    return ([base64.b64encode(f'{{"index": {share.index}, "value": "{int_to_base64(share.value)}"}}'.encode('utf-8')).decode('utf-8') for share in shares])

app = QApplication([])

window = DecryptorMainWindow()
window.show()

app.exec()
