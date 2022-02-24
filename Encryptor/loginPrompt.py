import tkinter.messagebox as mb
from tkinter import Label, StringVar, Entry, Button

from cryptography.fernet import InvalidToken

from Encryptor import Encryptor
from Encryptor.InternalKey import InternalKey, dumpKeys, loadKeys
from Encryptor.utils import clearWindow, pil_image_to_tkinter_image, quitHandler
from MainApplicationWindow import entry_point
from images import LockImg
from utils import centerWindow


def login_screen(window):
    clearWindow(window)
    window.iconphoto(False, pil_image_to_tkinter_image(LockImg))

    centerWindow(window)
    window.lift()

    # tkWindow.geometry('400x150')
    window.title('Login')
    window.protocol("WM_DELETE_WINDOW", lambda: quitHandler(window))

    # username label and text entry box
    Label(window, text="User Name").grid(row=0, column=0, padx=10, pady=10)
    global username
    username = StringVar(window)
    Entry(window, textvariable=username).grid(row=0, column=1, padx=1, pady=10)

    # password label and password entry box
    Label(window, text="Password").grid(row=1, column=0, padx=10, pady=1)
    global password
    password = StringVar(window)
    Entry(window, textvariable=password, show='*').grid(row=1, column=1, padx=1, pady=1)

    # Error Message Init
    login_info_message = StringVar(window)
    login_info_message.set("Please Login")
    infoLabel = Label(window, textvariable=login_info_message)
    infoLabel.grid(row=4, column=1, padx=1, pady=10)

    # login button
    Button(window, text="Login", command=lambda: validate_login(username, password, window)).grid(row=4,
                                                                                                  column=0,
                                                                                                  padx=10,
                                                                                                  pady=10)

    # New User Button
    Button(window, text='New User', command=lambda: new_login_screen(window)).grid(row=4, column=2, padx=10,
                                                                                   pady=10)

    centerWindow(window)
    window.mainloop()


def new_login_screen(window):
    # window.geometry('400x150')
    clearWindow(window)
    window.title('New User')
    window.protocol("WM_DELETE_WINDOW", lambda: quitHandler(window))

    # User Row
    Label(window, text="User Name").grid(row=0, column=0)
    newUserName = StringVar(window)
    Entry(window, textvariable=newUserName).grid(row=0, column=1)

    # Password Row 1
    Label(window, text="Password").grid(row=1, column=0)
    newPass1 = StringVar(window)
    Entry(window, textvariable=newPass1).grid(row=1, column=1)

    # Password Row 2
    Label(window, text="Confirm Password").grid(row=2, column=0)
    newPass2 = StringVar(window)
    Entry(window, textvariable=newPass2).grid(row=2, column=1)

    # Create User Button
    Button(window, text='Create New User',
           command=lambda: create_user(newUserName, newPass1, newPass2, window)).grid(row=3, column=2, padx=10,
                                                                                      pady=10)

    # Return To Login Screen Button
    Button(window, text='Return To Login', command=lambda: login_screen(window)).grid(row=3, column=0, padx=10,
                                                                                      pady=10)

    # User Message
    msgTxt = StringVar(window)
    msgTxt.set("Enter Username and Password")
    Label(window, textvariable=msgTxt).grid(row=3, column=1)
    centerWindow(window)
    window.mainloop()


def create_user(usernameIn, password_one_in, password_two_in, window):
    p1 = password_one_in.get()
    p2 = password_two_in.get()
    username = usernameIn.get()
    if p1 == p2 and len(p1) > 3:
        USERKEY = Encryptor.create_key(password=p1)
        writeKey = InternalKey(USERKEY, "Password Key", "The Key Generated from your password")
        KEYS = [writeKey]
        MAINFILE = username + '.db'
        dumpKeys(MAINFILE, KEYS, USERKEY)
        entry_point(window, MAINFILE, USERKEY, KEYS)


def validate_login(username, Password, window):
    password = Password.get()
    username = username.get()

    try:
        USERKEY = Encryptor.create_key(password=password)
        MAINFILE = username + '.db'
        KEYS = loadKeys(MAINFILE, USERKEY)
        entry_point(window, MAINFILE, USERKEY, KEYS)
    except FileNotFoundError:
        mb.showerror(title="Login Message", message="User not found")
    except InvalidToken:
        mb.showerror(title="Login Message", message="Incorrect Password")
