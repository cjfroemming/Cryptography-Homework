"""
================================================================================
Script Name: pwmanager.py
Description: This is a simple password manager designed as a project for EE 4940 - Introduction to Cryptography.

Author: Cooper Froemming
Email: coopefroem@gmail.com
Date Created: 12/20/2024
Last Updated: 12/20/2024
Version: 1.0.0

================================================================================
License:
SPDX-License-Identifier: MIT
================================================================================
Dependencies:
- Python >= 3.11.9
- pandas==2.2.3
- pycryptodome==3.21.0
- PyQt5==5.15.11
- PyQt5_sip==12.16.1
- qtwidgets==1.1
- qtpy==2.4.2
- Any other external libraries or tools.

To install dependencies:
`pip install -r requirements.txt`

================================================================================
Usage:
While in the same working directory as this script, run:
`python pwmanager.py`

================================================================================
Features:
- Login Screen
- New Account Creation
- User's master passwords are not stored.
- Master password hash verification using hashlib's SHA3-256.
- Password database encrypted using encryption key generated with PBKDF2_HMAC and user's master password.
- Editable interface for saving account information.

================================================================================
TODOs:
- Reject bad passwords (e.g. too short, no unique characters).
- Ensure this program is completely closed when the main window is exited.

================================================================================
Changelog:
- <Date>: <Version> - <Description of changes>
- 12/20/2024: 1.0.0 - Initial Release
================================================================================
"""

import pandas as pd
import hashlib
import json
import warnings
import time
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
import os
import sys
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QMainWindow,
    QPushButton,
    QVBoxLayout,
    QLineEdit,
    QLabel,
    QScrollArea,
    QHBoxLayout,
    QVBoxLayout,
    QFormLayout,
)
from PyQt5.QtCore import QSize, Qt, QTimer
from qtwidgets import PasswordEdit

global HASH_ITERATIONS
global CURRENT_SCRIPT_DIRECTORY

# Constants
CURRENT_SCRIPT_DIRECTORY = os.path.dirname(
    os.path.abspath(__file__)
)  # Get path of where the script is working.
HASH_ITERATIONS = 600000

# Placeholder for global variables.
encryption_key = None

# GUI Functions


def init_login_GUI():
    app = QApplication(sys.argv)
    loginWindow = LoginWindow()
    loginWindow.show()
    app.exec()
    return


class LoginWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.setFixedSize(QSize(400, 175))
        self.password_window = PasswordWindow()
        self.login_attempts = {}  # Track login attempts this session.
        self.show_login_screen()

    def create_button(self, text, callback):
        """Helper function to create QPushButton."""
        button = QPushButton(text)
        button.clicked.connect(callback)
        return button

    def show_login_screen(self):  # Initial Login screen
        self.password_field = PasswordEdit()
        self.username_field = QLineEdit()
        self.message_label = QLabel("Please login")

        login_layout = QFormLayout()
        login_layout.addWidget(self.message_label)
        login_layout.addRow("Username:", self.username_field)
        login_layout.addRow("Password:", self.password_field)
        login_container = QWidget()
        login_container.setLayout(login_layout)

        button_layout = QVBoxLayout()
        button_layout.addWidget(self.create_button("Login", self.login_button_pressed))
        button_layout.addWidget(
            self.create_button("Create a New Account", self.sign_up_button_pressed)
        )
        button_container = QWidget()
        button_container.setLayout(button_layout)

        main_layout = QVBoxLayout()
        main_layout.addWidget(login_container)
        main_layout.addWidget(button_container)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

    def login_button_pressed(self):
        """Handle login button press."""
        username = self.username_field.text()
        current_time = time.time()

        # Check if the user is in the login attempts tracker
        if username not in self.login_attempts:
            self.login_attempts[username] = []

        # Remove old attempts outside the time window (e.g., last 30 seconds)
        self.login_attempts[username] = [
            attempt
            for attempt in self.login_attempts[username]
            if current_time - attempt < 30
        ]

        # Check if too many attempts were made recently
        if (
            len(self.login_attempts[username]) >= 3
        ):  # Allow max 3 attempts in 30 seconds
            self.message_label.setText(
                "Too many attempts. Please wait 30 seconds before trying again."
            )
            QTimer.singleShot(
                30000, lambda: self.message_label.setText("Please login")
            )  # Go back to original message after 30 seconds.
            return

        # Record the current attempt
        self.login_attempts[username].append(current_time)

        if user_exists_in_master_database(username):
            salt = grab_salt_of_master_user(username)
            hash = hashlib.sha256(
                bytes(self.password_field.text(), "utf-8") + salt
            ).digest()  #
            stored_hash = master_password_database.loc[
                master_password_database["User"] == username, "Hash"
            ].values[0]
            if hash == stored_hash:  # password matches
                global encryption_key
                encryption_key = hashlib.pbkdf2_hmac(
                    "sha3_256",
                    bytes(self.password_field.text(), "utf-8"),
                    salt,
                    HASH_ITERATIONS,
                )
                print("Login successful.")
                self.password_window.set_user(username)
                self.password_window.set_database(get_database_of_user(username))
                self.password_window.display_passwords()
                self.password_window.show()
                self.password_window.reset_inactivity_timer()
                self.close()

            else:  # password does not match
                self.message_label.setText("Incorrect Username/Password")

        else:  # username does not match anything in database.
            self.message_label.setText("Incorrect Username/Password")

    def sign_up_button_pressed(self):
        """Handles the sign-up button being pressed."""
        self.show_sign_up_screen()

    def show_sign_up_screen(self):  # Initial Sign Up Screen
        """Display the sign-up screen."""
        self.username_field = QLineEdit()
        self.password_field = PasswordEdit()
        self.message_label = QLabel("Please create a new account.")

        sign_up_layout = QFormLayout()
        sign_up_layout.addWidget(self.message_label)
        sign_up_layout.addRow("Username:", self.username_field)
        sign_up_layout.addRow("Password:", self.password_field)

        sign_up_container = QWidget()
        sign_up_container.setLayout(sign_up_layout)
        sign_up_container.setLayout(sign_up_layout)

        button_layout = QVBoxLayout()
        button_layout.addWidget(
            self.create_button("Create Account", self.create_account_button_pressed)
        )
        button_layout.addWidget(self.create_button("Back", self.back_button_pressed))

        button_container = QWidget()
        button_container.setLayout(button_layout)

        main_layout = QVBoxLayout()
        main_layout.addWidget(sign_up_container)
        main_layout.addWidget(button_container)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

    def back_button_pressed(self):
        self.show_login_screen()  # return to the login screen.

    def create_account_button_pressed(self):
        """Handle account creation."""
        username = self.username_field.text()
        if user_exists_in_master_database(username):
            self.message_label.setText(
                "That username is taken, please choose another one."
            )
        else:
            password = self.password_field.text()
            if len(password) < 8:
                self.message_label.setText(
                    "Password must be at least 8 characters long."
                )
            else:
                salt = os.urandom(16)  # 16 byte random number.
                hash = hashlib.sha256(
                    bytes(self.password_field.text(), "utf-8") + salt
                ).digest()
                add_user_to_master_database(self.username_field.text(), hash, salt)
                save_database_to_file("masterpasswords.pkl", master_password_database)
                print("Account successfully created.")
                self.message_label.setText("Success! Your account has been created.")


class PasswordWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.__user__ = None
        self.__database__ = None

        self.UIDS = [0]

        # Inactivity timer logs user out if they do not do anything for 10 minutes.
        self.inactivity_timer = QTimer(self)
        self.inactivity_timer.setInterval(600000)  # 10 minutes (in milliseconds)
        self.inactivity_timer.timeout.connect(self.logout)

        self.setWindowTitle("Password Manager")
        self.resize(QSize(700, 500))

        self.init_ui()
        self.init_buttons()

    def init_ui(self):
        """Initialize main UI components"""
        self.password_layout = QVBoxLayout()
        self.password_container = QWidget()
        self.password_container.setMinimumWidth(300)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)

        self.data_layout = QHBoxLayout()
        self.data_container = QWidget()

        self.window_layout = QVBoxLayout()
        self.window_container = QWidget()

    def init_buttons(self):
        """Initialize buttons for window."""
        self.new_account_button = QPushButton()
        self.new_account_button.setText("New")
        self.new_account_button.setMaximumWidth(100)
        self.new_account_button.clicked.connect(self.create_new_account)

        self.logout_button = QPushButton()
        self.logout_button.setText("Logout")
        self.logout_button.setMaximumWidth(100)
        self.logout_button.clicked.connect(self.logout)

        self.window_layout.addWidget(
            self.logout_button
        )  # added to the top of the window.
        # new_account_button is added later, to be at the bottom of the window.

    def display_passwords(self):
        """Display all passwords of the user."""

        warnings.simplefilter(
            action="ignore", category=FutureWarning
        )  # supress a future warning that pandas gives.

        self.clear_password_display()

        # Add new passwords from database to the layout.
        for _, account in self.__database__.iterrows():
            password_interface = self.create_password_interface(account)
            self.password_layout.addWidget(password_interface)

        self.setup_layouts()

        warnings.simplefilter(
            action="default", category=FutureWarning
        )  # turn future warnings back on.

    def clear_password_display(self):
        """Removes all widgets from the password layout."""
        for i in reversed(range(self.password_layout.count())):
            widget = self.password_layout.itemAt(i).widget()
            if widget is not None:
                widget.deleteLater()

    def create_password_interface(self, account):
        """Creates a new instance of a PasswordInterface widget, and populates it with information from account input."""
        password_interface = PasswordInterface(self)
        password_interface.set_user(self.get_user())
        password_interface.set_database(self.__database__)
        password_interface.set_id_number(int(account[1]))

        password_interface.name_line.setText(decrypt_string(account[2]))
        password_interface.username_line.setText(decrypt_string(account[3]))
        password_interface.url_line.setText(decrypt_string(account[4]))
        password_interface.email_line.setText(decrypt_string(account[5]))
        password_interface.notes_line.setText(decrypt_string(account[6]))
        password_interface.password_line.setText(decrypt_string(account[7]))

        return password_interface

    def setup_layouts(self):
        """sets up layouts for the password"""
        self.password_container.setLayout(self.password_layout)
        self.data_layout.addWidget(self.password_container, 1)
        self.data_container.setLayout(self.data_layout)
        self.scroll_area.setWidget(self.data_container)

        self.window_layout.addWidget(self.scroll_area)
        self.window_layout.addWidget(
            self.new_account_button, 0, alignment=Qt.AlignCenter
        )
        self.window_container.setLayout(self.window_layout)

        self.setCentralWidget(self.window_container)

    def create_new_account(self):
        """Create a new account and add it to the database."""
        try:
            new_UID = int(find_max_UID(self.get_database())) + 1
        except ValueError:
            new_UID = 0

        user = self.get_user()
        add_to_password_database(
            user, new_UID, "", "", "", "", "", "", ""
        )  # add new account to database.
        self.set_database(get_database_of_user(user))

        # Create new UI element for the new account.
        new_account = PasswordInterface(self)
        new_account.set_user(user)
        new_account.set_id_number(new_UID)
        new_account.set_database(self.get_database())

        self.password_layout.addWidget(new_account)

        # Update UI
        self.window_container.update()
        # 10 ms delay to let window_container finish updating before moving the scrollbar.
        QTimer.singleShot(
            10,
            lambda: self.scroll_area.verticalScrollBar().setValue(
                self.scroll_area.verticalScrollBar().maximum()
            ),
        )

    def logout(self):
        """Logs the user out."""
        self.close()  # Close the PasswordWindow

        # Create and show the LoginWindow
        self.loginWindow = LoginWindow()
        self.loginWindow.show()

        # Clear the encryption key.
        global encryption_key
        encryption_key = None

    # Setters and Getters.
    def set_database(self, database):
        self.__database__ = database

    def get_database(self):
        return self.__database__

    def set_user(self, username):
        self.__user__ = username

    def get_user(self):
        return self.__user__

    # Timer Functions.
    def reset_inactivity_timer(self):
        """Starts or resets the inactivity timer."""
        self.inactivity_timer.start()

    def keyPressEvent(self, event):
        """Handles key press events to reset the timer."""
        self.reset_inactivity_timer()  # Reset timer on any key press
        super().keyPressEvent(event)

    def mouseMoveEvent(self, event):
        """Handles mouse move events to reset the timer."""
        self.reset_inactivity_timer()  # Reset timer on mouse movement
        super().mouseMoveEvent(event)

    def mousePressEvent(self, event):
        """Handles mouse press events to reset the timer."""
        self.reset_inactivity_timer()  # Reset timer on mouse click
        super().mousePressEvent(event)

    def wheelEvent(self, event):
        """Handles mouse wheel events to reset the timer."""
        self.reset_inactivity_timer()
        super().wheelEvent(event)

    def moveEvent(self, event):
        """Handles window moving events to reset the timer."""
        self.reset_inactivity_timer()
        super().moveEvent(event)

    def closeEvent(self, event):
        """Handles the window close event."""
        self.inactivity_timer.stop()  # Stop the timer when the window is closed
        event.accept()


class PasswordInterface(QWidget):
    """Interface for edititing and displaying one of the master user's account."""

    def __init__(self, parent=None):
        super().__init__()

        self.setMinimumHeight(250)

        self.__user__ = None
        self.__uid__ = 0  # changable unique id number.
        self.__database__ = pd.DataFrame(
            columns=[
                "User",
                "Password UID",
                "Name",
                "Website Username",
                "URL",
                "Email",
                "Notes",
                "Encrypted Password",
                "Salt",
            ]
        )
        self.parent = parent

        self.init_ui()
        self.init_buttons()
        self.setup_layout()

    def init_ui(self):
        """Initializes account input/display lines."""
        self.notEditable = True  # cannot edit lines by default.

        self.name_line = QLineEdit()
        self.name_line.setReadOnly(self.notEditable)
        self.username_line = QLineEdit()
        self.username_line.setReadOnly(self.notEditable)
        self.url_line = QLineEdit()
        self.url_line.setReadOnly(self.notEditable)
        self.email_line = QLineEdit()
        self.email_line.setReadOnly(self.notEditable)
        self.password_line = PasswordEdit()
        self.password_line.setReadOnly(self.notEditable)
        self.notes_line = QLineEdit()
        self.notes_line.setReadOnly(self.notEditable)

    def init_buttons(self):
        """Initializes buttons for the interface."""
        self.edit_or_save_button = QPushButton(
            "Edit"
        )  # alternates between being an edit button and a save button.
        self.edit_or_save_button.clicked.connect(self.edit_or_save_button_pressed)
        self.edit_or_save_button.setMaximumWidth(75)

        self.delete_button = QPushButton("Delete")
        self.delete_button.setMaximumWidth(75)
        self.delete_button.clicked.connect(self.delete_button_pressed)

    def setup_layout(self):
        self.button_layout = QHBoxLayout()
        self.button_container = QWidget()
        self.button_layout.addWidget(self.delete_button)
        self.button_layout.addWidget(self.edit_or_save_button)
        self.button_layout.setAlignment(Qt.AlignLeft)
        self.button_container.setLayout(self.button_layout)

        self.password_layout = QFormLayout()
        self.password_layout.addRow("Name:", self.name_line)
        self.password_layout.addRow("Username:", self.username_line)
        self.password_layout.addRow("URL:", self.url_line)
        self.password_layout.addRow("Email:", self.email_line)
        self.password_layout.addRow("Password:", self.password_line)
        self.password_layout.addRow("Notes:", self.notes_line)
        self.password_layout.addWidget(self.button_container)
        self.password_layout.setSpacing(10)
        self.setLayout(self.password_layout)

    def edit_or_save_button_pressed(self):
        """Change from edit mode to save mode and vice versa."""
        if self.notEditable:  # change to save mode
            self.notEditable = False  # swap
            self.edit_or_save_button.setText("Save")
        else:  # change to edit mode
            self.notEditable = True
            self.saveDataToDatabase()
            self.edit_or_save_button.setText("Edit")

        # update lines to reflect the mode change.
        self.name_line.setReadOnly(self.notEditable)
        self.username_line.setReadOnly(self.notEditable)
        self.url_line.setReadOnly(self.notEditable)
        self.email_line.setReadOnly(self.notEditable)
        self.password_line.setReadOnly(self.notEditable)
        self.notes_line.setReadOnly(self.notEditable)

    def saveDataToDatabase(self):
        """Saves current information to the database."""

        # Get the index of this password from the overall password database.
        filtered_database = password_database.loc[
            (password_database["User"] == self.__user__)
            & (password_database["Password UID"] == self.__uid__)
        ]
        if not filtered_database.empty:
            index = filtered_database.index.values[0]
        else:
            index = 0

        # Encrypts and saves information to database, and then saves it to the file.
        salt = os.urandom(16)
        password_database.at[index, "Name"] = encrypt_string(
            self.name_line.text(), salt
        )
        password_database.at[index, "Website Username"] = encrypt_string(
            self.username_line.text(), salt
        )
        password_database.at[index, "URL"] = encrypt_string(self.url_line.text(), salt)
        password_database.at[index, "Email"] = encrypt_string(
            self.email_line.text(), salt
        )
        password_database.at[index, "Encrypted Password"] = encrypt_string(
            self.password_line.text(), salt
        )
        password_database.at[index, "Notes"] = encrypt_string(
            self.notes_line.text(), salt
        )
        password_database.at[index, "Salt"] = salt
        save_database_to_file("passwords.pkl", password_database)
        return

    def delete_button_pressed(self):
        """Opens up a confirmation window that handles the deletion process."""
        self.delete_window = deleteWindow(self.parent)
        self.delete_window.set_user(self.getUser())
        self.delete_window.setUid(self.getIdNumber())
        self.delete_window.show()

    # Setters and Getters.
    def getIdNumber(self):
        return self.__uid__

    def set_user(self, user):
        self.__user__ = user

    def getUser(self):
        return self.__user__

    def set_id_number(self, value):  # must be an integer.
        if isinstance(value, int):
            self.__uid__ = value
        else:
            print("ERROR: PasswordInterface.set_id_number() needs integer input.")
            return -1

    def set_database(self, database):
        self.__database__ = database


class deleteWindow(QMainWindow):
    """Window confirming whether you are sure you wish to delete an account."""

    def __init__(self, parent=None):
        super().__init__()

        self.__user__ = None
        self.__uid__ = None
        self.parent = parent

        self.setFixedSize(QSize(250, 100))

        self.message_label = QLabel()
        self.message_label.setAlignment(Qt.AlignCenter)
        self.message_label.setText("Are you sure you wish to delete this?")

        self.yes_button = QPushButton()
        self.yes_button.setText("Yes")
        self.yes_button.released.connect(self.yes_button_released)
        self.no_button = QPushButton()
        self.no_button.setText("No")
        self.no_button.released.connect(self.no_button_released)

        self.button_layout = QHBoxLayout()
        self.button_layout.addWidget(self.yes_button)
        self.button_layout.addWidget(self.no_button)
        self.button_container = QWidget()
        self.button_container.setLayout(self.button_layout)

        self.window_layout = QVBoxLayout()
        self.window_layout.addWidget(self.message_label)
        self.window_layout.addWidget(self.button_container)
        self.window_container = QWidget()
        self.window_container.setLayout(self.window_layout)

        self.setCentralWidget(self.window_container)

    def yes_button_released(self):
        """Deletes database specific database entry, and then closes this window."""

        # Delete account from database.
        password_database.drop(
            password_database.loc[
                (password_database["User"] == self.getUser())
                & (password_database["Password UID"] == self.getUid())
            ].index.values[0],
            inplace=True,
        )
        save_database_to_file("passwords.pkl", password_database)

        # Find parent window that contains the password interface, and delete that instance.
        parent_window = self.parent
        if isinstance(parent_window, PasswordWindow):
            for i in range(parent_window.password_layout.count()):
                widget = parent_window.password_layout.itemAt(i).widget()
                if (
                    isinstance(widget, PasswordInterface)
                    and widget.getIdNumber() == self.getUid()
                ):
                    parent_window.password_layout.removeWidget(widget)
                    widget.deleteLater()
                    break
            # Update parent windows information to reflect this change.
            parent_window.set_database(get_database_of_user(self.getUser()))
            parent_window.display_passwords()

        self.destroy()

    def no_button_released(self):
        """Close this window."""
        self.destroy()

    # Setters and Getters
    def set_user(self, user):
        self.__user__ = user

    def getUser(self):
        return self.__user__

    def setUid(self, uid):
        self.__uid__ = uid

    def getUid(self):
        return self.__uid__


## Database functions


def init_database():  # load database files, or if there are none, generate an empty database (but not the file).
    """Loads databases from file, or creates new databases if none can be found."""
    global password_database
    global master_password_database

    master_password_database_path = CURRENT_SCRIPT_DIRECTORY + "\masterpasswords.pkl"

    if os.path.exists(master_password_database_path):
        master_password_database = pd.read_pickle(master_password_database_path)
    else:
        master_password_database = pd.DataFrame(columns=["User", "Hash", "Salt"])

    """
    Master Password Database: Stores data for logging into password manager, notably the master password.
        User - Unique username to login with master password.
        Hash - salted hash of master password using PHBDK2
        Salt - salt to be put on user input for password. each user gets their own salt.
    """

    password_database_path = CURRENT_SCRIPT_DIRECTORY + "\passwords.pkl"
    if os.path.exists(password_database_path):
        password_database = pd.read_pickle(password_database_path)
    else:
        password_database = pd.DataFrame(
            columns=[
                "User",
                "Password UID",
                "Name",
                "Website Username",
                "URL",
                "Email",
                "Notes",
                "Encrypted Password",
                "Salt",
            ]
        )
    """
    Password Database: Stores all passwords and other useful information.
        User - Username used for login in with master password.
        Password UID - unique identification number generated with each password entry. only on a user-by-user basis.
        Website Username (encrypted) - Username entry displayed for user.
        URL (encrypted) - URL of website
        Email (encrypted) - email of account
        Notes (encrypted) - any other notes the user cares about.
        Encrypted Password (encrypted) - password encrypted using key with salt.
        Salt - the salt used in encrypting each entry in the database.
    """


def user_exists_in_master_database(username):
    """Checks whether a user exists in the master database."""
    df = master_password_database
    if (df["User"] == username).any():
        return True
    else:
        return False


def grab_salt_of_master_user(username):
    """Gets the salt of a user in the master database."""
    df = master_password_database
    salt = df.loc[df["User"] == username, "Salt"].values[0]
    return salt


def add_user_to_master_database(user, hash, salt):
    """Adds a user to the master database."""
    master_password_database.loc[len(master_password_database)] = [
        user,
        hash,
        salt,
    ]  # initial test values.
    return


def add_to_password_database(
    user,
    password_UID,
    name,
    website_username,
    url,
    email,
    notes,
    encrypted_password,
    salt,
):
    """Adds an account entry to the password database."""
    if password_database.empty:
        index = 0
    else:
        index = password_database.index.max() + 1
    password_database.loc[index] = [
        user,
        password_UID,
        name,
        website_username,
        url,
        email,
        notes,
        encrypted_password,
        salt,
    ]  # initial test values.
    return


def get_database_of_user(user):
    """For the entire password database, return the subset that includes a specific master user."""
    user_passwords = password_database.loc[password_database["User"] == user]
    return user_passwords


def find_max_UID(df):
    """Find the highest UID value in a given database."""
    uid_max = df["Password UID"].max()
    return uid_max


def save_database_to_file(name, df):
    """Saves the database as a file to the same directory as the overall script."""
    name = CURRENT_SCRIPT_DIRECTORY + "\\" + name
    df.to_pickle(name)
    return


def encrypt_string(string, salt):
    """Encrypt a string using AES in GCM mode."""
    cipher = AES.new(encryption_key, AES.MODE_GCM)
    string_length = bytes(
        str(len(string)), "utf-8"
    )  # needs to be in bytes for json file.
    header = b"header"
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(bytes((string + str(salt)), "utf-8"))

    json_k = ["nonce", "header", "ciphertext", "tag", "string length"]
    json_v = [
        b64encode(x).decode("utf-8")
        for x in (cipher.nonce, header, ciphertext, tag, string_length)
    ]  # nonce is 16 bytes.
    result = json.dumps(dict(zip(json_k, json_v)))
    return result


def decrypt_string(json_input):
    """Decrypt a string using AES in GCM mode"""
    b64 = json.loads(json_input)
    json_k = ["nonce", "header", "ciphertext", "tag", "string length"]
    jv = {k: b64decode(b64[k]) for k in json_k}
    cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=jv["nonce"])
    cipher.update(jv["header"])

    plaintext = cipher.decrypt_and_verify(
        jv["ciphertext"], jv["tag"]
    )  # decrypt and verify the information is correct.

    # remove salt from plaintext.
    string_length = int(jv["string length"])
    plaintext = str(plaintext)
    plaintext = plaintext[2 : 2 + string_length]
    return plaintext


def main():
    init_database()
    init_login_GUI()
    return


main()
