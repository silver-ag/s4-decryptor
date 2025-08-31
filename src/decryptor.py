# TODO:
# - profiling!
# - add encryption window

from PyQt6.QtCore import QSize, Qt, QTimer, QRunnable, QThreadPool, pyqtSlot, pyqtSignal, QObject, QRect
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea, QPlainTextEdit, QTextEdit, QPushButton, QMessageBox, QSizePolicy, QDialog, QDialogButtonBox, QSpacerItem
from PyQt6.QtGui import QColor, QPalette, QFont, QFontDatabase

import json
import itertools
import base64
from shamir_ss import generate_text_shares, reconstruct_text_secret
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

PROJECT_NAME = '[projectname]'
PRIME_MODULUS = 9531*2**9531-1 # 2874-digit prime, larger than 256**1024 # (previously: 4122429552750669*2**16567+1 # 5003-digit prime, larger than 256**2048)

try:
    with open("data/private_key.pem", "rb") as key_file:
        PRIVATE_KEY = serialization.load_pem_private_key(key_file.read(), password=None)
except:
    PRIVATE_KEY = None
with open("data/public_key.pem", "rb") as key_file:
    PUBLIC_KEY = serialization.load_pem_public_key(key_file.read())

#shamirs.share.__eq__ = lambda self, other: self.index == other.index and self.value == other.value and self.modulus == other.modulus

class Secret:
    def __init__(self, text, keys_used):
        self.text = text
        self.keys_used = keys_used
    def __hash__(self):
        return hash(f'{self.text}|{self.keys_used}')

class Key:
    def __init__(self, index, chunks):
        self.index = index
        self.chunks = chunks
    @staticmethod
    def from_base64(b64str):
        try:
            b64str += '='*((4-(len(b64str)%4))%4) # fix broken padding - this is useful because it's easy to accidentally copy and paste without padding
            k_json = json.loads(base64.b64decode(b64str).decode('utf-8'))
            return Key(k_json['index'], [base64_to_int(chunk) for chunk in k_json['chunks']])
        except Exception as e:
            print(f'Key.from_base64: {e}')
            return None
    def b64str(self):
        return base64.b64encode(f'{{"index": {self.index}, "chunks": ["{"\",\"".join([int_to_base64(self.chunks[i]) for i in range(len(self.chunks))])}"]}}'.encode('utf-8')).decode('utf-8')
    def library_format(self):
        return (self.index, self.chunks)
    def __eq__(self, other):
        return isinstance(other, Key) and self.index == other.index and len(self.chunks) == len(other.chunks) and all([self.chunks[i] == other.chunks[i] for i in range(len(self.chunks))])
    def __hash__(self):
        return hash(self.b64str())

# Subclass QMainWindow to customize your application's main window
class DecryptorMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.keys = {} # key: keybox
        self.secrets = {} # secret: secretbox

        self.popups_enabled = True
        self.threadpool = QThreadPool()

        self.setWindowTitle(f'{PROJECT_NAME} decryptor')
        top_layout = QVBoxLayout()
        title = BorderlessLabel(f'{PROJECT_NAME} decryptor')
        title.setStyleSheet('font-size: 30px')
        topbarlayout = QHBoxLayout()
        topbarlayout.addWidget(title)
        if PRIVATE_KEY is not None:
            topbarlayout.addSpacerItem(QSpacerItem(1, 1, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))
            encryptbutton = QPushButton('encrypt')
            topbarlayout.addWidget(encryptbutton)
        topbar = BorderlessWidget()
        topbar.setLayout(topbarlayout)
        top_layout.addWidget(topbar)
        self.secrets_layout = QHBoxLayout()
        self.secrets_widget = QLabel('loading ...')
        self.secrets_widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.secrets_widget.setLayout(self.secrets_layout)
        secrets_scroll_widget = QScrollArea()
        secrets_scroll_widget.setWidget(self.secrets_widget)
        secrets_scroll_widget.setWidgetResizable(True)
        secrets_area_layout = QVBoxLayout()
        secrets_area_layout.addWidget(BorderlessLabel('SECRETS'))
        secrets_area_layout.addWidget(secrets_scroll_widget)
        secrets_area = BorderlessWidget()
        secrets_area.setLayout(secrets_area_layout)
        top_layout.addWidget(secrets_area)
        self.keys_layout = QHBoxLayout()
        self.keys_layout.addWidget(AddKeyBox())
        keys_widget = QWidget()
        keys_widget.setLayout(self.keys_layout)
        keys_scroll_widget = QScrollArea()
        keys_scroll_widget.setWidget(keys_widget)
        keys_scroll_widget.setWidgetResizable(True)
        keys_area_layout = QVBoxLayout()
        keys_area_layout.addWidget(BorderlessLabel('KEYS'))
        keys_area_layout.addWidget(keys_scroll_widget)
        keys_area = BorderlessWidget()
        keys_area.setLayout(keys_area_layout)
        top_layout.addWidget(keys_area)
        
        central_widget = QWidget()
        central_widget.setLayout(top_layout)
        # Set the central widget of the Window.
        self.setCentralWidget(central_widget)
        
        self.resize(640, 640)

    def addSecret(self, secret_str, keys_used):
        try:
            print(secret_str)
            secret_json = json.loads(secret_str)
            secret = Secret(secret_json['secret'], keys_used)
            #sig = base64.b64decode(secret_json['signature'])
        except Exception as e:
            print(f'addSecret: {e}')
            return
        #try:
        #    PUBLIC_KEY.verify(sig, secret.text.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        #except InvalidSignature:
        #    self.messageBox("found a secret, but it doesn't have a valid {PROJECT_NAME} signature - the data may be tampered with or corrupted", 'signature warning')
        new_secret_box = SecretBox(secret)
        self.secrets_layout.addWidget(new_secret_box)
        self.secrets[secret] = new_secret_box
        self.viewSecretBox(secret)

    def addKey(self, key_string):
        try:
            key = Key.from_base64(key_string)
            key.number = len(self.keys)
            print(key.number)
        except Exception as e:
            print(e)
            self.messageBox(f'not a valid {PROJECT_NAME} key', 'invalid key')
            return False

        for other_key in self.keys:
            if other_key == key:
                self.messageBox('you already have that key', 'key already present')
                return False
        
        self.checkForSecrets(key)
        new_key_box = KeyBox(key)
        self.keys_layout.addWidget(new_key_box)#self.keys_layout.insertWidget(self.keys_layout.count()-1, new_key_box)
        self.keys[key] = new_key_box

        with open('data/saved_keys.json', 'r') as key_file:
            key_data = json.load(key_file)
        if key.b64str() not in key_data:
            key_data.append(key.b64str())
        with open('data/saved_keys.json', 'w') as key_file:
            json.dump(key_data, key_file)

        return True

    def removeKey(self, key):
        removed_number = key.number
        self.keys_layout.removeWidget(self.keys[key])
        self.keys[key].deleteLater()
        self.keys.pop(key)

        with open('data/saved_keys.json', 'r') as key_file:
            key_data = json.load(key_file)
        key_data.remove(key.b64str())
        with open('data/saved_keys.json', 'w') as key_file:
            json.dump(key_data, key_file)
        
        self.regenerateExistingSecrets() # remove any secrets that depended on that key

        for key in self.keys: # update remaining key numbers
            if key.number > removed_number:
                key.number -= 1

    def removeSecret(self, secret):
        self.secrets_layout.removeWidget(self.secrets[secret])
        self.secrets[secret].deleteLater()
        self.secrets.pop(secret)

    def checkForSecrets(self, new_key):
        for quantity in range(len(self.keys)+1):
            for combo in itertools.combinations(self.keys, quantity):
                try:
                    print([k.number for k in combo] + [new_key.number])
                    new_secret = decrypt_from_keys(list(combo) + [new_key])
                    self.addSecret(new_secret, list(combo) + [new_key])
                except Exception as e:
                    print(f'checkForSecrets: {e}')
                    pass

    def regenerateExistingSecrets(self):
        self.popups_enabled = False
        for secret in [s for s in self.secrets]:
            self.removeSecret(secret)
        for quantity in range(len(self.keys)):
            for combo in itertools.combinations(self.keys, quantity):
                try:
                    new_secret = decrypt_from_keys(list(combo))
                    self.addSecret(new_secret, list(combo))
                except Exception as e:
                    print(f'regenerateExistingSecrets: {e}')
                    pass
        self.popups_enabled = True

    def loadSavedKeys(self):
        self.popups_enabled = False # don't pop up messages about saved keys while loading them
        try:
            with open('data/saved_keys.json', 'r') as key_file:
                existing_keys = json.load(key_file)
                print(f'loading {len(existing_keys)} keys from file')
                for key in existing_keys:
                    print('adding from file')
                    self.addKey(key)
        except FileNotFoundError:
            with open('data/saved_keys.json', 'w+') as key_file: # create file if it doesn't exist
                key_file.write('[]')
        self.popups_enabled = True
        self.secrets_widget.setText('')

    def isKeyUsed(self, key):
        for secret in self.secrets:
            if key in secret.keys_used:
                return True
        return False

    def messageBox(self, message, title):
        if self.popups_enabled:
            dlg = QMessageBox(self)
            dlg.setWindowTitle(title)
            dlg.setText(message)
            dlg.exec()

    def viewSecretBox(self, secret):
        if self.popups_enabled:
            dlg = QMessageBox(self)
            dlg.setWindowTitle(f'{PROJECT_NAME} secret')
            dlg.setText(f'{PROJECT_NAME} secret')
            dlg.setInformativeText(secret.text)
            dlg.exec()

class BorderlessWidget(QWidget):
    pass

class BorderlessLabel(QLabel):
    pass

class SecretBox(QWidget):
    def __init__(self, secret):
        super().__init__()
        layout = QVBoxLayout()
        textbox = QPlainTextEdit(secret.text)
        textbox.setReadOnly(True)
        numslinelayout = QHBoxLayout()
        for key in secret.keys_used:
            numslinelayout.addWidget(NumLabel(key))
        numslinelayout.addSpacerItem(QSpacerItem(1, 1, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))
        numsline = BorderlessWidget()
        numsline.setLayout(numslinelayout)
        layout.addWidget(textbox)
        layout.addWidget(numsline)
        self.setLayout(layout)

class KeyBox(QWidget):
    def __init__(self, key):
        super().__init__()
        self.key = key
        number_area = NumLabel(key)
        x_button = QPushButton('X')
        x_button.clicked.connect(self.delete)
        topbarlayout = QHBoxLayout()
        topbarlayout.addWidget(number_area)
        topbarlayout.addWidget(x_button)
        topbar = BorderlessWidget()
        topbar.setLayout(topbarlayout)
        layout = QVBoxLayout()
        layout.addWidget(topbar)
        textbox = QPlainTextEdit(key.b64str())
        textbox.setReadOnly(True)
        textbox.setMinimumSize(150,150)
        layout.addWidget(textbox)
        self.setLayout(layout)
    def delete(self):
        if self.window().isKeyUsed(self.key):
            if not self.ConfirmDelete().exec():
                return # don't delete
        self.window().removeKey(self.key)
    class ConfirmDelete(QDialog):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("warning")
            QBtn = QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel

            self.buttonBox = QDialogButtonBox(QBtn)
            self.buttonBox.accepted.connect(self.accept)
            self.buttonBox.rejected.connect(self.reject)

            layout = QVBoxLayout()
            message = QLabel("this key is used for a secret you've unlocked. if you delete it, the secret will be deleted too.")
            layout.addWidget(message)
            layout.addWidget(self.buttonBox)
            self.setLayout(layout)
            

class AddKeyBox(QWidget):
    def __init__(self):
        super().__init__()
        add_button = QPushButton('+')
        add_button.clicked.connect(self.add_button_pressed)
        self.text_box = QPlainTextEdit()
        self.text_box.setPlaceholderText('paste a new key here')
        self.text_box.setMinimumSize(150,150)
        layout = QVBoxLayout()
        layout.addWidget(self.text_box)
        layout.addWidget(add_button)
        self.setLayout(layout)
    def add_button_pressed(self):
        if self.window().addKey(self.text_box.toPlainText()):
            self.text_box.clear()

class NumLabel(QLabel):
    def __init__(self, key):
        super().__init__()
        self.key = key
        self.timer = QTimer(self)
        self.timer.setSingleShot(False)
        self.timer.setInterval(5) # in milliseconds, so 5000 = 5 seconds
        self.timer.timeout.connect(self.updateNumber)
        self.timer.start()
    def updateNumber(self): # test
        self.setText(str(self.key.number))

def string_to_int(string):
    return int.from_bytes(string.encode('utf-8'), 'little')

def int_to_string(integer):
    return integer.to_bytes((integer.bit_length() + 7) // 8, 'little').decode('utf-8')

def int_to_base64(integer):
    return base64.b64encode(integer.to_bytes((integer.bit_length()+7)//8,'little')).decode('utf-8')

def base64_to_int(b64str):
    return int.from_bytes(base64.b64decode(b64str), 'little')

def make_keys(value, required, quantity):
    #sig = base64.b64encode(PRIVATE_KEY.sign(value.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())).decode('utf-8')
    keys = [Key(share[0], share[1]) for share in generate_text_shares(f'{{"secret": "{value}"}}', required, quantity)]
    return [key.b64str() for key in keys]

def decrypt_from_keys(keys):
    return reconstruct_text_secret([key.library_format() for key in keys])

app = QApplication([])
QFontDatabase.addApplicationFont('data/FiraCode-Medium.ttf')
QFontDatabase.addApplicationFont('data/FiraCode-Bold.ttf')
with open('data/matrix.qss', 'r') as stylesheet:
    style = stylesheet.read()
    app.setStyleSheet(style)
window = DecryptorMainWindow()
window.show()
timer = QTimer()
timer.timeout.connect(lambda: window.loadSavedKeys())
timer.setSingleShot(True)
timer.start(1)

app.exec()
