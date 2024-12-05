import numpy as np
import pandas as pd
from PyQt5.QtWidgets import QApplication, QWidget
import sys

def init_database():
    database = pd.DataFrame(columns=['Name','URL','email','Encrypted Password','Notes'])
    print(database)
    return

def init_GUI():
    app = QApplication(sys.argv)

    window = QWidget()
    window.show()

    app.exec()
    return

def main(): 
    init_database()
    init_GUI()
    return

main()
