import numpy as np
import pandas as pd
import hashlib
from Crypto.Cipher import AES
import os
import sys
from pathlib import Path
from PyQt5.QtWidgets import QApplication, QWidget, QMainWindow, QPushButton, QVBoxLayout, QLineEdit, QLabel
from PyQt5.QtCore import QSize
from qtwidgets import PasswordEdit

global ITERATIONS
global program_path
global encryption_key #not sure if keeping this as a global variable is ok or not...
program_path = os.path.dirname(os.path.abspath(__file__)) #Get path of where the script is working.
ITERATIONS = 500000 #Hash ITERATIONS.

#GUI functions

def init_GUI(): 
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    app.exec()
    return

class MainWindow(QMainWindow) :
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Password Manager")

        self.show_login_screen()

        self.setFixedSize(QSize(400,300))
        self.setMinimumSize(QSize(400,300))

    def show_login_screen(self): # Initial Login screen
        self.password_input = PasswordEdit()

        self.username_input = QLineEdit()

        self.label = QLabel()
        self.label.setText("Please Login")

        self.loginButton = QPushButton()
        self.loginButton.setText("Login")
        self.loginButton.clicked.connect(self.login_button_pressed)

        self.signUpButton = QPushButton()
        self.signUpButton.setText("Create a New Account")
        self.signUpButton.clicked.connect(self.sign_up_button_pressed)

        self.backButton = QPushButton()
        self.backButton.setText("Back")
        self.backButton.clicked.connect(self.back_button_pressed)

        login_layout = QVBoxLayout()
        login_layout.addWidget(self.label)
        login_layout.addWidget(self.username_input)
        login_layout.addWidget(self.password_input)
        login_layout.addWidget(self.loginButton)
        login_layout.addWidget(self.signUpButton)
        login_widget = QWidget()
        login_widget.setLayout(login_layout)
        self.setCentralWidget(login_widget)

    def login_button_pressed(self):
        username = self.username_input.text()
        if user_exists_in_database(username, master_password_database) : 
            salt = grab_salt_of_user(username, master_password_database)
            hash = hashlib.sha256(bytes(self.password_input.text(), 'utf-8') + salt)
            hash = hash.digest()
            encryption_key = hashlib.pbkdf2_hmac('sha3_256',bytes(self.password_input.text(), 'utf-8'), salt, ITERATIONS)
            stored_hash = master_password_database.loc[master_password_database["User"] == username, "Hash"].values[0]
            if (hash == stored_hash) :
                print("Correct Password!")
            else :
                self.label.setText("Incorrect Username/Password")
        else: #username does not match anything in database.
            self.label.setText("Incorrect Username/Password")

    def sign_up_button_pressed(self):
        self.show_sign_up_screen()

    def show_sign_up_screen(self): # Initial Sign Up Screen
        self.password_input = PasswordEdit()
        self.username_input = QLineEdit()
        self.label = QLabel()
        self.label.setText("Please Create a new account.")

        self.createAccountButton = QPushButton()
        self.createAccountButton.setText("Create Account")
        self.createAccountButton.clicked.connect(self.create_account_button_pressed)

        self.backButton = QPushButton()
        self.backButton.setText("Back")
        self.backButton.clicked.connect(self.back_button_pressed)

        sign_up_layout = QVBoxLayout()
        sign_up_layout.addWidget(self.label)
        sign_up_layout.addWidget(self.username_input)
        sign_up_layout.addWidget(self.password_input)
        sign_up_layout.addWidget(self.createAccountButton)
        sign_up_layout.addWidget(self.backButton)
        sign_up_widget = QWidget()
        sign_up_widget.setLayout(sign_up_layout)
        sign_up_widget.setLayout(sign_up_layout)

        self.setCentralWidget(sign_up_widget)

    def back_button_pressed(self):
        self.show_login_screen()
        
    def create_account_button_pressed(self):
        username = self.username_input.text()
        if user_exists_in_database(username,master_password_database) :
            self.label.setText("That username is taken, please choose another one.")
        else:
            self.label.setText("...") #incase things take a while.
            salt = os.urandom(16) # 16 byte random number.
            hash = hashlib.sha256(bytes(self.password_input.text(), 'utf-8') + salt)
            hash = hash.digest()
            encryption_key = hashlib.pbkdf2_hmac('sha3_256',bytes(self.password_input.text(), 'utf-8'), salt, ITERATIONS) #create an encryption key for each password.
            add_user_to_database(self.username_input.text(),hash,salt,master_password_database)
            save_database_to_file("masterpasswords.pkl",master_password_database)
            print('created account!')
            self.label.setText("Success! Your account has been created.")


## Database functions

def init_database(): #load database files, or if there are none, generate an empty database (but not the file).
    global password_database
    global master_password_database

    master_password_database_path = program_path + "\masterpasswords.pkl"

    if os.path.exists(master_password_database_path) : master_password_database = pd.read_pickle(master_password_database_path)
    else : master_password_database = pd.DataFrame(columns=['User','Hash','Salt'])

    password_database_path = program_path + "\passwords.csv"
    if os.path.exists(password_database_path) : password_database = pd.read_pickle(password_database_path)
    else : password_database = pd.DataFrame(columns=['User','Name','URL','Email','Notes','Encrypted Password','Salt'])

    #master_password_database.loc[len(master_password_database)] = ['Cooper','hashabc','saltxyz'] # initial test values.
    return

def user_exists_in_database(username,df) :
    if ((df["User"] == username).any()) : 
        return True
    else :
        return False

def grab_salt_of_user(username,df) :
    salt = df.loc[df["User"] == username, "Salt"].values[0]
    return salt

def add_user_to_database(username,hash,salt,df):
    df.loc[len(df)] = [username,hash,salt] # initial test values.
    return

def save_database_to_file(name,df):
    name = program_path + '\\' + name 
    df.to_pickle(name)
    return

def encrypt_password(password, salt) :
        cipher =  AES.new(encryption_key, AES.MODE_CFB)
        encrypted_password = cipher.encrypt(password + salt)
        return encrypted_password        


def main(): 
    init_database()
    print("Database:")
    print(master_password_database)
    init_GUI()
    #master_password_database.loc[len(master_password_database)] = ['Cooper','hashabc','saltxyz'] # add item to database
    return

main()
