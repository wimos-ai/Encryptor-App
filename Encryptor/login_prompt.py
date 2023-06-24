"""Module responsible for the login prompt"""
import tkinter.messagebox as mb
from tkinter import Label, StringVar, Entry, Button, Tk
from typing import Any

from cryptography.fernet import InvalidToken

from fernet_encryption import Encryptor
from internal_key import InternalKey
from main_window import MainWindowC
from utils import center_window
from utils import clear_window, pil_image_to_tkinter_image, quit_handler
from window_icon import LockImg


class CreateLoginScreen:
    """Login Screen"""
    __slots__ = "window", "parent_window", "user_name", "password1", "password2"

    def __init__(self, window: Tk, parent_window: Any):
        self.user_name = StringVar(window)
        self.password1 = StringVar(window)
        self.password2 = StringVar(window)
        self.parent_window = parent_window
        self.window = window

    def draw(self) -> None:
        """Draws the screen on the underlying window"""
        clear_window(self.window)
        self.window.title('New User')
        self.window.protocol("WM_DELETE_WINDOW", lambda: quit_handler(self.window))

        # User Row
        Label(self.window, text="User Name").grid(row=0, column=0)
        Entry(self.window, textvariable=self.user_name).grid(row=0, column=1)

        # Password Row 1
        Label(self.window, text="Password").grid(row=1, column=0)
        Entry(self.window, textvariable=self.password1).grid(row=1, column=1)

        # Password Row 2
        Label(self.window, text="Confirm Password").grid(row=2, column=0)
        Entry(self.window, textvariable=self.password2).grid(row=2, column=1)

        # Create User Button
        Button(self.window, text='Create New User',
               command=self.create_user).grid(row=3, column=2, padx=10, pady=10)

        # Return To Log in Screen Button
        Button(self.window, text='Return To Login', command=self.parent_window.draw).grid(row=3,
                                                                                          column=0,
                                                                                          padx=10,
                                                                                          pady=10)

        # User Message
        msg_txt = StringVar(self.window)
        msg_txt.set("Enter Username and Password")
        Label(self.window, textvariable=msg_txt).grid(row=3, column=1)
        center_window(self.window)

    def create_user(self) -> None:
        """Creates the user database"""
        password_one = self.password1.get()
        password_two = self.password2.get()
        username = self.user_name.get()
        if password_one == password_two and len(password_one) > 3:
            usr_key = Encryptor.create_key(password=password_one)
            write_key = InternalKey(usr_key, "Password Key", "The Key Generated from your password")
            keys = [write_key]
            main_db_file = username + '.db'
            InternalKey.dump_keys(main_db_file, keys, usr_key)
            self.parent_window.draw()
        elif password_one != password_two:
            mb.showerror(title="New Account Error", message="Passwords do not match")

        elif len(password_one) <= 3:
            mb.showerror(
                title="New Account Error",
                message="Passwords must be four characters or more"
            )

        else:
            mb.showerror(title="New Account Error", message="Generic Failure")


class LoginScreen:
    """Class responsible for the Login screen"""
    __slots__ = "window", "user_name", "password", "new_user_window", "main_window"

    def __init__(self, window: Tk):
        self.window = window
        self.user_name = StringVar(window)
        self.password = StringVar(window)
        self.new_user_window = CreateLoginScreen(window, self)
        self.main_window = None

    def draw(self) -> None:
        """Draws the window onto the underlying Tk object"""
        clear_window(self.window)
        self.window.iconphoto(False, pil_image_to_tkinter_image(LockImg))

        self.window.lift()

        self.window.title('Login')
        self.window.protocol("WM_DELETE_WINDOW", lambda: quit_handler(self.window))

        # username label and text entry box
        Label(self.window, text="User Name").grid(row=0, column=0, padx=10, pady=10)
        Entry(self.window, textvariable=self.user_name).grid(row=0, column=1, padx=1, pady=10)

        # password label and password entry box
        Label(self.window, text="Password").grid(row=1, column=0, padx=10, pady=1)
        Entry(self.window, textvariable=self.password, show='*').grid(row=1,
                                                                      column=1,
                                                                      padx=1,
                                                                      pady=1)

        # Error Message Init
        login_info_message = StringVar(self.window)
        login_info_message.set("Please Login")
        info_label = Label(self.window, textvariable=login_info_message)
        info_label.grid(row=4, column=1, padx=1, pady=10)

        # login button
        Button(self.window, text="Login", command=self.validate_login).grid(row=4,
                                                                            column=0,
                                                                            padx=10,
                                                                            pady=10)

        # New User Button
        Button(self.window, text='New User', command=self.new_user_window.draw) \
            .grid(row=4, column=2, padx=10, pady=10)
        center_window(self.window)

    def validate_login(self) -> None:
        """Attempts login and if successful, launches main application"""
        password = self.password.get()
        user_name = self.user_name.get()
        try:
            user_key = Encryptor.create_key(password=password)
            main_file = user_name + '.db'
            keys = InternalKey.load_keys(main_file, user_key)
            MainWindowC(self.window, main_file, user_key, keys).draw()
        except FileNotFoundError:
            mb.showerror(title="Login Message", message="User not found")
        except InvalidToken:
            mb.showerror(title="Login Message", message="Incorrect Password")
