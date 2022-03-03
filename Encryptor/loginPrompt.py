import tkinter.messagebox as mb
from tkinter import Label, StringVar, Entry, Button, Tk

from cryptography.fernet import InvalidToken

from FernetEncryption import Encryptor
from InternalKey import InternalKey, dumpKeys, loadKeys
from MainApplicationWindow import entry_point
from WindowIcon import LockImg
from utils import centerWindow
from utils import clearWindow, pil_image_to_tkinter_image, quitHandler


def login_screen(window: Tk) -> None:
    clearWindow(window)
    window.iconphoto(False, pil_image_to_tkinter_image(LockImg))

    window.lift()

    window.title('Login')
    window.protocol("WM_DELETE_WINDOW", lambda: quitHandler(window))

    # username label and text entry box
    Label(window, text="User Name").grid(row=0, column=0, padx=10, pady=10)
    username = StringVar(window)
    Entry(window, textvariable=username).grid(row=0, column=1, padx=1, pady=10)

    # password label and password entry box
    Label(window, text="Password").grid(row=1, column=0, padx=10, pady=1)
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


def new_login_screen(window: Tk) -> None:
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


def create_user(usernameIn: StringVar, password_one_in: StringVar, password_two_in: StringVar, window: Tk) -> None:
    password_one = password_one_in.get()
    password_two = password_two_in.get()
    username = usernameIn.get()
    if password_one == password_two and len(password_one) > 3:
        user_key = Encryptor.create_key(password=password_one)
        writeKey = InternalKey(user_key, "Password Key", "The Key Generated from your password")
        KEYS = [writeKey]
        main_db_file = username + '.db'
        dumpKeys(main_db_file, KEYS, user_key)
        entry_point(window, main_db_file, user_key, KEYS)
    elif password_one != password_two:
        mb.showerror(title="New Account Error", message="Passwords do not match")

    elif len(password_one) <= 3:
        mb.showerror(title="New Account Error", message="Passwords must be four characters or more")

    else:
        mb.showerror(title="New Account Error", message="Generic Failure")


def validate_login(user_name: StringVar, password: StringVar, window: Tk) -> None:
    password = password.get()
    user_name = user_name.get()
    try:
        user_key = Encryptor.create_key(password=password)
        main_file = user_name + '.db'
        KEYS = loadKeys(main_file, user_key)
        entry_point(window, main_file, user_key, KEYS)
    except FileNotFoundError:
        mb.showerror(title="Login Message", message="User not found")
    except InvalidToken:
        mb.showerror(title="Login Message", message="Incorrect Password")
