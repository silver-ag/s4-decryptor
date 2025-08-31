# TODO:
# - profiling!
# - add encryption window

from PyQt6.QtCore import QSize, Qt, QTimer, QRunnable, QThreadPool, pyqtSlot, pyqtSignal, QObject, QRect
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QScrollArea, QPlainTextEdit, QTextEdit, QPushButton, QMessageBox, QSizePolicy, QDialog, QDialogButtonBox, QSpacerItem, QTabWidget, QSpinBox
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
from cryptography.hazmat.primitives import hashes

PROJECT_NAME = '[projectname]'

#try:
#    with open("data/private_key.pem", "rb") as key_file:
#        PRIVATE_KEY = serialization.load_pem_private_key(key_file.read(), password=None)
#except:
#    PRIVATE_KEY = None
#with open("data/public_key.pem", "rb") as key_file:
#    PUBLIC_KEY = serialization.load_pem_public_key(key_file.read())
#

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
        return base64.b64encode(('{"index": ' + str(self.index) + ', "chunks": ["' + '","'.join([int_to_base64(self.chunks[i]) for i in range(len(self.chunks))]) + '"]}').encode('utf-8')).decode('utf-8')
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
        self.secret = '' # secret: secretbox

        self.popups_enabled = True
        self.threadpool = QThreadPool() # TODO - is this being used?

        self.setWindowTitle(f'{PROJECT_NAME} decryptor')
        tabs = QTabWidget()
        top_layout = QVBoxLayout()
        title = BorderlessLabel(f'{PROJECT_NAME} decryptor')
        title.setStyleSheet('font-size: 30px')
        topbarlayout = QHBoxLayout()
        topbarlayout.addWidget(title)
        topbar = BorderlessWidget()
        topbar.setLayout(topbarlayout)
        top_layout.addWidget(topbar)
        self.secrets_layout = QHBoxLayout()
        self.secrets_widget = QLabel('loading ...')
        self.secrets_widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.secrets_widget.setLayout(self.secrets_layout)
        policy = self.secrets_widget.sizePolicy()
        policy.setVerticalStretch(1)
        self.secrets_widget.setSizePolicy(policy)
        top_layout.addWidget(self.secrets_widget)
        self.keys_layout = QHBoxLayout()
        keys_widget = BorderlessWidget()
        keys_widget.setLayout(self.keys_layout)
        keys_scroll_widget = QScrollArea()
        keys_scroll_widget.setWidget(keys_widget)
        keys_scroll_widget.setWidgetResizable(True)
        keys_area_layout = QHBoxLayout()
        keys_area_layout.addWidget(keys_scroll_widget)
        keys_area_layout.addWidget(AddKeyBox())
        keys_area = QWidget()
        keys_area.setLayout(keys_area_layout)
        policy = keys_area.sizePolicy()
        policy.setVerticalStretch(1)
        keys_area.setSizePolicy(policy)
        top_layout.addWidget(keys_area)
        decrypt_central_widget = BorderlessWidget()
        decrypt_central_widget.setLayout(top_layout)

        top_layout = QVBoxLayout()
        title = BorderlessLabel(f'{PROJECT_NAME} encryptor')
        title.setStyleSheet('font-size: 30px')
        topbarlayout = QHBoxLayout()
        topbarlayout.addWidget(title)
        topbar = BorderlessWidget()
        topbar.setLayout(topbarlayout)
        top_layout.addWidget(topbar)
        secret_input_layout = QHBoxLayout()
        self.secret_input_widget = QPlainTextEdit()
        self.secret_input_widget.textChanged.connect(self.encrypt)
        self.secret_input_widget.setLayout(secret_input_layout)
        policy = self.secret_input_widget.sizePolicy()
        policy.setVerticalStretch(1)
        self.secret_input_widget.setSizePolicy(policy)
        top_layout.addWidget(self.secret_input_widget)
        self.encrypt_keys_layout = QHBoxLayout()
        keys_widget = BorderlessWidget()
        keys_widget.setLayout(self.encrypt_keys_layout)
        keys_scroll_widget = QScrollArea()
        keys_scroll_widget.setWidget(keys_widget)
        keys_scroll_widget.setWidgetResizable(True)
        keys_area_layout = QHBoxLayout()
        keys_area_layout.addWidget(keys_scroll_widget)
        number_input_layout = QVBoxLayout()
        self.encrypt_num_shares = QSpinBox()
        self.encrypt_num_shares.setRange(1,99)
        self.encrypt_shares_needed = QSpinBox()
        self.encrypt_shares_needed.setRange(1,99)
        self.encrypt_num_shares.valueChanged.connect(self.encrypt)
        self.encrypt_shares_needed.valueChanged.connect(self.encrypt)
        self.encrypt_num_shares.valueChanged.connect(lambda v: self.encrypt_shares_needed.setRange(1,v))
        number_input_layout.addWidget(BorderlessLabel('total keys'))
        number_input_layout.addWidget(self.encrypt_num_shares)
        number_input_layout.addWidget(BorderlessLabel('keys needed to decrypt'))
        number_input_layout.addWidget(self.encrypt_shares_needed)
        number_input = QWidget()
        number_input.setLayout(number_input_layout)
        keys_area_layout.addWidget(number_input)
        keys_area = QWidget()
        keys_area.setLayout(keys_area_layout)
        policy = keys_area.sizePolicy()
        policy.setVerticalStretch(1)
        keys_area.setSizePolicy(policy)
        top_layout.addWidget(keys_area)
        encrypt_central_widget = BorderlessWidget()
        encrypt_central_widget.setLayout(top_layout)
        
        top_layout = QVBoxLayout()
        title = BorderlessLabel(f'{PROJECT_NAME} verifier')
        title.setStyleSheet('font-size: 30px')
        topbarlayout = QHBoxLayout()
        topbarlayout.addWidget(title)
        topbar = BorderlessWidget()
        topbar.setLayout(topbarlayout)
        top_layout.addWidget(topbar)
        verify_input_layout = QHBoxLayout()
        self.verify_input_widget = QPlainTextEdit()
        self.verify_input_widget.textChanged.connect(self.verify)
        self.verify_input_widget.setLayout(secret_input_layout)
        policy = self.verify_input_widget.sizePolicy()
        policy.setVerticalStretch(1)
        self.verify_input_widget.setSizePolicy(policy)
        top_layout.addWidget(self.verify_input_widget)
        self.verify_result_widget = QLabel()
        self.verify_result_widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
        policy = self.verify_result_widget.sizePolicy()
        policy.setVerticalStretch(1)
        self.verify_result_widget.setSizePolicy(policy)
        top_layout.addWidget(self.verify_result_widget)
        verify_central_widget = BorderlessWidget()
        verify_central_widget.setLayout(top_layout)

        tabs.addTab(decrypt_central_widget, 'decrypt')
        tabs.addTab(encrypt_central_widget, 'encrypt')
        tabs.addTab(verify_central_widget, 'verify')
        self.setCentralWidget(tabs)
        
        self.resize(640, 640)

    def addSecret(self, secret_str, keys_used):
        try:
            secret_json = json.loads(secret_str)
            secret = base64.b64decode(secret_json['secret'].encode('utf-8')).decode('utf-8')
            #sig = base64.b64decode(secret_json['signature'])
        except Exception as e:
            print(f'addSecret: {e}')
            return
        #try:
        #    PUBLIC_KEY.verify(sig, secret.text.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        #except InvalidSignature:
        #    self.messageBox("found a secret, but it doesn't have a valid {PROJECT_NAME} signature - the data may be tampered with or corrupted", 'signature warning')
        #new_secret_box = SecretBox(secret)
        #self.secrets_layout.addWidget(new_secret_box)
        #self.secrets[secret] = new_secret_box
        self.viewSecretBox(secret)
        self.secret = secret
        self.secrets_widget.setText(secret)

    def addKey(self, key_string):
        try:
            key = Key.from_base64(key_string)
            key.number = len(self.keys)
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

    def removeSecret(self):
        #self.secrets_layout.removeWidget(self.secrets[secret])
        #self.secrets[secret].deleteLater()
        #self.secrets.pop(secret)
        self.secret = 'no secret found yet'
        self.secrets_widget.setText(self.secret)

    def checkForSecrets(self, new_key):
        for quantity in range(len(self.keys)+1):
            for combo in itertools.combinations(self.keys, quantity):
                try:
                    new_secret = decrypt_from_keys(list(combo) + [new_key])
                    self.addSecret(new_secret, list(combo) + [new_key])
                except Exception as e:
                    print(f'checkForSecrets: {e}')
                    pass

    def regenerateExistingSecrets(self):
        self.popups_enabled = False
        self.removeSecret()
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
                for key in existing_keys:
                    self.addKey(key)
        except FileNotFoundError:
            with open('data/saved_keys.json', 'w+') as key_file: # create file if it doesn't exist
                key_file.write('[]')
        self.popups_enabled = True
        if self.secret == '':
            self.removeSecret()

    def messageBox(self, message, title):
        if self.popups_enabled:
            dlg = QMessageBox(self)
            dlg.setWindowTitle(title)
            dlg.setText(message)
            dlg.exec()

    def viewSecretBox(self, secret):
        print(1)
        if self.popups_enabled:
            dlg = QMessageBox(self)
            dlg.setWindowTitle(f'{PROJECT_NAME} secret')
            dlg.setText(f'secret found')
            #dlg.setInformativeText(secret)
            dlg.exec()

    def encrypt(self):
        secret = self.secret_input_widget.toPlainText()
        quantity = self.encrypt_num_shares.value()
        required = self.encrypt_shares_needed.value()
        keys = [Key.from_base64(k) for k in make_keys(secret, required, quantity)]
        for i in range(len(keys)):
            keys[i].number = i
        while self.encrypt_keys_layout.count():
            child = self.encrypt_keys_layout.takeAt(0)
            if child.widget():
              child.widget().deleteLater()
        for key in keys:
            self.encrypt_keys_layout.addWidget(KeyBox(key))

    def verify(self):
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(self.verify_input_widget.toPlainText().encode('utf-8'))
        self.verify_result_widget.setText(hasher.finalize().hex())

class BorderlessWidget(QWidget):
    pass

class BorderlessLabel(QLabel):
    pass

class SecretBox(QWidget):
    def __init__(self, secret):
        super().__init__()
        layout = QVBoxLayout()
        textbox = QPlainTextEdit(secret)
        textbox.setReadOnly(True)
        numslinelayout = QHBoxLayout()
        for key in secret.keys_used:
            numslinelayout.addWidget(NumLabel(key))
        numslinelayout.addSpacerItem(QSpacerItem(1, 1, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))
        numsline = BorderlessWidget()
        numsline.setLayout(numslinelayout)
        layout.addWidget(textbox)
        #layout.addWidget(numsline)
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
        self.setFixedWidth(200)
        layout.addWidget(textbox)
        self.setLayout(layout)
    def delete(self):
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
        self.setFixedWidth(200)
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
    try:
        #sig = base64.b64encode(PRIVATE_KEY.sign(value.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())).decode('utf-8')
        keys = [Key(share[0], share[1]) for share in generate_text_shares(f'{{"secret": "{base64.b64encode(value.encode("utf-8")).decode("utf-8")}"}}', required, quantity)]
        return [key.b64str() for key in keys]
    except Exception as e: # happens briefly if the number of shares goes below the number needed
        print(e)
        return []

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
