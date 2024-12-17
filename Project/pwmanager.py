import numpy as np
import pandas as pd
import hashlib
from Crypto.Cipher import AES
import os
import sys
from pathlib import Path
from PyQt5.QtWidgets import QApplication, QWidget, QMainWindow, QPushButton, QVBoxLayout, QLineEdit, QLabel, QScrollArea, QHBoxLayout, QVBoxLayout, QSizePolicy
from PyQt5.QtCore import QSize, Qt
from qtwidgets import PasswordEdit
import traceback

global ITERATIONS
global program_path
global encryption_key #not sure if keeping this as a global variable is ok or not...
program_path = os.path.dirname(os.path.abspath(__file__)) #Get path of where the script is working.
ITERATIONS = 500000 #Hash ITERATIONS.

''' 
TODO:

    LoginWindow
    -Define Criteria for bad passwords (e.g. too short, no unique characters.)
    -Reject bad master passwords.

    PasswordInterface
    -Add a Logout button.
        -where?
    -Save information to database when "save" is clicked
        -Encrypt the passwords when this happens.
        -Give it a unique identifier.
    -Add a delete button to interface.
        -Make sure database handles completely empty entries.
            -what to do with changes in unique identifier (index)?

    General
    -Make there can only be one program running at a time?

'''


#GUI functions

def init_login_GUI(): 
    app = QApplication(sys.argv)

    #loginWindow = LoginWindow()
    debug = PasswordWindow()
    debug.show()
    #loginWindow.show()

    app.exec()
    return

def init_pw_GUI():
    return

class LoginWindow(QMainWindow) :
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Password Manager")

        self.show_login_screen() #BRING BACK


        self.passwordWindow = PasswordWindow()

        

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
                print("Correct Password.")
                self.passwordWindow.show()
                self.destroy()
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
            add_user_to_master_database(self.username_input.text(),hash,salt,master_password_database)
            save_database_to_file("masterpasswords.pkl",master_password_database)
            print('created account!')
            self.label.setText("Success! Your account has been created.")

class PasswordWindow(QMainWindow) :
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Password Manager")

        pw1 = PasswordInterface()
        pw2 = PasswordInterface()

        password_layout = QVBoxLayout()

        for pw in range(0,10): #make this dependant on however many passwords one has.
            pwI = PasswordInterface()
            pwI.setIdNumber(pw)
            password_layout.addWidget(pwI)

        # password_layout.addWidget(pw1)
        # password_layout.addWidget(pw2)

        password_container = QWidget()
        password_container.setLayout(password_layout)


        scroll_area = QScrollArea()
        scroll_area.setWidget(password_container)


        header = headerWidget()
        header.sizeHint().setHeight(500)

        header_scroller = QScrollArea()
        header_scroller.setWidget(header)
        header_scroller.verticalScrollBar().hide()
        header_scroller.horizontalScrollBar().hide()
        # header_scroller.sizePolicy().setVerticalPolicy(QSizePolicy.Fixed)
        # header_scroller.adjustSize()
        header_scroller.setMinimumSize(QSize(200,45))

        scroll_area.sizePolicy().setVerticalPolicy(QSizePolicy.Expanding)


        header_scroller_container = QWidget()
        #header_scroller.minimumSize().setHeight(100)

        #what the fuck is going on here. why won't the sizes work.

        scroll_area.horizontalScrollBar().valueChanged.connect(lambda val,bar=header_scroller: move_other_scrollbar(val,bar))

        #header_scroller.setHorizontalScrollBar(scroll_area.horizontalScrollBar())

        window_layout = QVBoxLayout()
        window_layout.addWidget(header_scroller,0)
        window_layout.addWidget(scroll_area,1)

        #window_layout.maximumSize().setHeight(10)

        window_container = QWidget()
        window_container.setLayout(window_layout)
        #window_container.resize(500,10)

        self.setCentralWidget(window_container)


        #self.setMinimumSize(QSize(800,600))

        def move_other_scrollbar(val, bar):
            bar.horizontalScrollBar().setValue(val)




class PasswordInterface(QWidget) : #interface for 
    def __init__(self):
        super().__init__()

        self.__id_number__ = 0 #changable unique id number.
        self.notEditable = True #cannot edit lines by default.

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
        self.edit_or_save_button = QPushButton()
        self.edit_or_save_button.setText("Edit")
        self.edit_or_save_button.clicked.connect(self.edit_or_save_button_pressed)
        self.delete_button = QPushButton()
        self.delete_button.setText("X")
        self.delete_button.setMaximumWidth(20)
        self.delete_button.clicked.connect(self.delete_button_pressed)

        self.password_layout = QHBoxLayout()
        self.password_layout.addWidget(self.delete_button)
        self.password_layout.addWidget(self.name_line)
        self.password_layout.addWidget(self.username_line)
        self.password_layout.addWidget(self.url_line)
        self.password_layout.addWidget(self.email_line)
        self.password_layout.addWidget(self.password_line)
        self.password_layout.addWidget(self.notes_line)
        self.password_layout.addWidget(self.edit_or_save_button)
        self.setLayout(self.password_layout)

    def edit_or_save_button_pressed(self):
        if (self.notEditable) : # change to save mode
            self.notEditable = False #swap
            self.edit_or_save_button.setText("Save")
        else : # change to edit mode
            self.notEditable = True
            print(self.getIdNumber())
            self.edit_or_save_button.setText("Edit")

        #update 
        self.name_line.setReadOnly(self.notEditable)
        self.username_line.setReadOnly(self.notEditable)
        self.url_line.setReadOnly(self.notEditable)
        self.email_line.setReadOnly(self.notEditable)
        self.password_line.setReadOnly(self.notEditable)
        self.notes_line.setReadOnly(self.notEditable)

    def delete_button_pressed(self):
        self.delete_window = deleteWindow()
        self.delete_window.show()
        return

    def getIdNumber(self):
        return self.__id_number__

    def setIdNumber(self, value): #must be an integer.
        if isinstance(value, int):
            self.__id_number__ = value
        else :
            print("ERROR: PasswordInterface.setIdNumber() needs integer input.")
            return -1

    def save_data_to_database(self):
        #TODO: send data into database.
        return



class deleteWindow(QMainWindow) :
    def __init__(self):
        super().__init__()
        
        self.label = QLabel()
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setText("Are you sure you wish to delete this?")

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
        self.window_layout.addWidget(self.label)
        self.window_layout.addWidget(self.button_container)
        self.window_container = QWidget()
        self.window_container.setLayout(self.window_layout)

        self.setCentralWidget(self.window_container)

        self.setFixedSize(QSize(250,100))

    def yes_button_released(self) :
        #TODO: delete database entry here
        return
        
    def no_button_released(self):
        self.destroy()


class headerWidget(QWidget) : 
    def __init__(self):
        super().__init__()

        self.name_label = QLabel()
        self.name_label.setText("Name:                  ")
        self.username_label = QLabel()
        self.username_label.setText("Username:                ")
        self.url_label = QLabel()
        self.url_label.setText("URL:                     ")
        self.email_label = QLabel()
        self.email_label.setText("Email:                   ")
        self.password_label = QLabel()
        self.password_label.setText("Password:                     ")
        self.notes_label = QLabel()
        self.notes_label.setText("Notes:                             ")
        self.spacer = QLabel()

        self.header_layout = QHBoxLayout()
        self.header_layout.addWidget(self.spacer)
        self.header_layout.addWidget(self.name_label)
        self.header_layout.addWidget(self.username_label)
        self.header_layout.addWidget(self.url_label)
        self.header_layout.addWidget(self.email_label)
        self.header_layout.addWidget(self.password_label)
        self.header_layout.addWidget(self.notes_label)
        self.header_layout.addWidget(self.spacer)
        self.header_layout.setSpacing(50)
        self.setLayout(self.header_layout)





## Database functions

def init_database(): #load database files, or if there are none, generate an empty database (but not the file).
    global password_database
    global master_password_database

    master_password_database_path = program_path + "\masterpasswords.pkl"

    if os.path.exists(master_password_database_path) : master_password_database = pd.read_pickle(master_password_database_path)
    else : master_password_database = pd.DataFrame(columns=['User','Hash','Salt'])

    password_database_path = program_path + "\passwords.csv"
    if os.path.exists(password_database_path) : password_database = pd.read_pickle(password_database_path)
    else : password_database = pd.DataFrame(columns=['User','Website Username','URL','Email','Notes','Encrypted Password','Salt'])

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

def add_user_to_master_database(username,hash,salt,df):
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
    init_login_GUI()
    #master_password_database.loc[len(master_password_database)] = ['Cooper','hashabc','saltxyz'] # add item to database
    return

main()
