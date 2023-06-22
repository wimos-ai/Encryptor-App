import pickle
import tkinter.messagebox as mb
from tkinter import IntVar, Tk, Toplevel, StringVar, Button, Radiobutton,\
    Label, Entry, Frame, LabelFrame, LEFT, RIGHT, TOP
from tkinter.filedialog import askopenfilename, asksaveasfilename
from typing import Final

from PIL import ImageOps
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken

from fernet_encryption import Encryptor
from internal_key import dump_keys, InternalKey, load_keys
from trash_can_icon import TrashCanImg
from window_icon import LockImg
from arrow_icon import ARROW_IMG
from utils import file_guard, clear_window, pil_image_to_tkinter_image


class MainWindowC:
    __slots__ = ("page", "key_choice", "keys", "window", "user_file", "user_key", "key_frame")

    __KEYS_PER_PAGE: Final[int] = 8

    def __init__(self, window: Tk | Toplevel, file: str, user_key: Fernet, keys: list[InternalKey]):
        self.key_choice = IntVar(value=0)
        self.page = 0
        self.window = window
        self.user_file = file
        self.user_key = user_key
        self.keys = keys
        self.key_frame = LabelFrame(self.window, text="Keys")

    def encrypt_file_cb(self) -> None:
        file: str = askopenfilename()

        if file_guard(file, self.user_file):
            mb.showerror(title="Encryption Error", message="Cannot Do Encryption Methods on Login File")
            return
        try:
            Encryptor.encrypt_file(file, self.keys[self.key_choice.get()].fernetKey)
        except FileNotFoundError:
            mb.showerror(title="Encryption Error", message="Failed to get file from user")
            return
        mb.showinfo(title="Encryption Status", message=f"Successfully Encrypted {file}")

    def decrypt_file_cb(self) -> None:
        file = askopenfilename()

        if file == '':
            return

        if file_guard(file, self.user_file):
            mb.showerror(title="Encryption Error", message="Cannot Do Encryption Methods on Login File")
            return

        for key in self.keys:
            try:
                Encryptor.decrypt_file(file, key.fernetKey)
                mb.showinfo(title="Decryption Status",
                            message=f"Decryption of file {file} Successful with key: {key.name}")
                return
            except InvalidToken:
                continue
            except FileNotFoundError:
                mb.showerror(title="Decryption Error", message=f"Failed to open file: {file}")
                return
        mb.showerror(title="Decryption Error", message=f"Decryption of {file} Unsuccessful!")

    def export_key_cb(self) -> None:
        if self.key_choice.get() == 0:
            mb.showerror(title="Export Error", message="Cannot Export Default Key")
            return
        file = asksaveasfilename(defaultextension=".key",
                                 filetypes=(("key file", "*.key"), ("All Files", "*.*")))

        if file == '':
            return

        try:
            with open(file, 'wb') as usr_file:
                # TODO: Do not use a static password of 0 instead have pop-up ask for password
                usr_file.write(
                    Encryptor.encrypt_data(
                        pickle.dumps(self.keys[self.key_choice.get()], protocol=pickle.HIGHEST_PROTOCOL),
                        Encryptor.create_key(password='0')
                    )
                )
        except FileNotFoundError:
            mb.showerror(title="Export Error", message=f"File: {file} not found!")

    def load_key_cb(self) -> None:
        file = askopenfilename()
        if file == '':
            return
        try:
            with open(file, 'rb') as usr_file:
                contents = usr_file.read()
        except FileNotFoundError:
            mb.showerror(title="Key Load Error", message=f"File: {file} not found")

        try:
            new_key = pickle.loads(Encryptor.decrypt_data(contents, Encryptor.create_key(password='0')))
        except InvalidToken:
            mb.showerror(title="Key Load Error", message="Could not decode file")
            return
        self.keys.append(new_key)
        dump_keys(self.user_file, self.keys, self.user_key)
        self.display_keys()

    def new_random_key_cb(self) -> None:
        root = Toplevel()
        root.iconphoto(False, pil_image_to_tkinter_image(LockImg))
        root.protocol("WM_DELETE_WINDOW", root.destroy)

        # username label and text entry box
        Label(root, text="Key Name").grid(row=0, column=0, padx=10, pady=10)
        key_name = StringVar(root)
        Entry(root, textvariable=key_name).grid(row=0, column=1, padx=1, pady=10)

        # password Description and Description entry box
        Label(root, text="Key Description").grid(row=1, column=0, padx=10, pady=1)
        key_description = StringVar(root)
        Entry(root, textvariable=key_description).grid(row=1, column=1, padx=10, pady=1)

        def confirm_key():
            self.keys.append(InternalKey(Encryptor.create_random_key(), key_name.get(), key_description.get()))
            dump_keys(self.user_file, self.keys, self.user_key)
            self.display_keys()
            root.destroy()

        Button(root, text="Confirm", command=confirm_key).grid(row=2, column=1, padx=1, pady=1)

    def key_from_pass_cb(self) -> None:
        root = Toplevel()
        root.iconphoto(False, pil_image_to_tkinter_image(LockImg))
        root.protocol("WM_DELETE_WINDOW", root.destroy)

        # username label and text entry box
        Label(root, text="Key Name").grid(row=0, column=0, padx=10, pady=10)
        key_name = StringVar(root)
        Entry(root, textvariable=key_name).grid(row=0, column=1, padx=1, pady=10)

        # Description label and Description entry box
        Label(root, text="Key Description").grid(row=1, column=0, padx=10, pady=1)
        key_description = StringVar(root)
        Entry(root, textvariable=key_description).grid(row=1, column=1, padx=10, pady=1)

        Label(root, text="Password").grid(row=2, column=0, padx=10, pady=1)
        key_password = StringVar(root)
        Entry(root, textvariable=key_password).grid(row=2, column=1, padx=10, pady=1)

        def confirm_key():
            key = Encryptor.create_key(password=key_password.get())
            self.keys.append(InternalKey(key, key_name.get(), key_description.get()))
            dump_keys(self.user_file, self.keys, self.user_key)
            self.display_keys()
            root.destroy()

        Button(root, text="Confirm", command=confirm_key).grid(row=3, column=1, padx=1, pady=1)

    def change_usr_pass_cb(self) -> None:
        root = Toplevel()
        root.iconphoto(False, pil_image_to_tkinter_image(LockImg))
        root.protocol("WM_DELETE_WINDOW", root.destroy)

        # username label and text entry box
        Label(root, text="New Password").grid(row=0, column=0, padx=10, pady=10)
        pass_1 = StringVar(root)
        Entry(root, textvariable=pass_1).grid(row=0, column=1, padx=1, pady=10)

        # Description label and Description entry box
        Label(root, text="Confirm New Password").grid(row=1, column=0, padx=10, pady=1)
        pass_2 = StringVar(root)
        Entry(root, textvariable=pass_2).grid(row=1, column=1, padx=10, pady=1)

        def change_app_pass_confirm():
            password_one = pass_1.get()
            password_two = pass_2.get()
            if password_one == password_two and len(password_one) >= 4:
                new_key = Encryptor.create_key(password=pass_2.get())
                self.keys[0] = InternalKey(new_key, self.keys[0].name, self.keys[0].description)
                self.user_key = new_key
                dump_keys(self.user_file, self.keys, self.user_key)
                root.destroy()
            elif password_one != password_two:
                mb.showerror(title="Password Change Error", message="Passwords do not match")

            elif len(password_one) <= 3:
                mb.showerror(title="Password Change Error", message="Passwords must be four characters or more")

            else:
                mb.showerror(title="Password Change Error", message="Generic Failure")

        Button(root, text="Confirm", command=change_app_pass_confirm).grid(row=3, column=1, padx=1, pady=1)

    def edit_key_cb(self) -> None:
        key_edit_idx = int(self.key_choice.get())
        if key_edit_idx == 0:
            mb.showerror(title="Key Edit Error", message="Cannot Edit Default Key")
            return
        root = Toplevel()
        root.iconphoto(False, pil_image_to_tkinter_image(LockImg))
        root.protocol("WM_DELETE_WINDOW", root.destroy)
        root.lift()
        root.attributes("-topmost", True)
        root.after(1, lambda: root.focus_force)

        Label(root, text="Edit Name").grid(row=0, column=0, padx=10, pady=10)

        key_name = StringVar(root, value=self.keys[key_edit_idx].name)
        Entry(root, textvariable=key_name).grid(row=0, column=1, padx=1, pady=10)

        # Description label and Description entry box
        Label(root, text="Edit Description").grid(row=1, column=0, padx=10, pady=1)

        key_description = StringVar(root, value=self.keys[key_edit_idx].description)
        Entry(root, textvariable=key_description).grid(row=1, column=1, padx=10, pady=1)

        def delete_cb():
            self.keys.remove(self.keys[key_edit_idx])
            dump_keys(self.user_file, self.keys, self.user_key)
            self.display_keys()
            root.destroy()

        delete_button = Button(root, text="Delete Key", command=delete_cb)
        delete_button.image = pil_image_to_tkinter_image(TrashCanImg)
        delete_button.grid(column=2, row=0, columnspan=2, rowspan=2, sticky='NESW', padx=10, pady=10)

        def confirm_cb():
            self.keys[key_edit_idx].name = key_name.get()
            self.keys[key_edit_idx].description = key_description.get()
            dump_keys(self.user_file, self.keys, self.user_key)
            self.display_keys()
            root.destroy()

        Button(root, text="Confirm Changes", command=confirm_cb).grid(column=1, row=2, sticky='NESW', padx=10, pady=10)

    def draw(self) -> None:
        clear_window(self.window)

        # Init Key Display
        self.key_frame.pack(fill="both", expand="yes", padx=10, pady=10)
        self.key_frame.configure(bg='gray63')
        self.keys = load_keys(self.user_file, self.user_key)
        self.display_keys()

        # Init Options Frame
        options_frame = LabelFrame(self.window, text="Options")
        options_frame.configure(bg='gray63')
        options_frame.pack(fill="both", expand=True, padx=10, pady=10, side=LEFT)
        self.display_options(options_frame)

    def display_options(self, frame) -> None:
        bkground = frame["background"]
        left_frame = Frame(frame, bg=bkground)
        left_frame.pack(side=LEFT, fill="both", expand=True)
        right_frame = Frame(frame, bg=bkground)
        right_frame.pack(side=RIGHT, fill="both", expand=True)

        button_pack_args = {'fill': 'both', 'side': TOP, 'expand': True, 'padx': 10, 'pady': 3}

        Button(left_frame, text="Encrypt File", command=self.encrypt_file_cb).pack(**button_pack_args)

        Button(right_frame, text="Decrypt File", command=self.decrypt_file_cb).pack(**button_pack_args)

        Button(left_frame, text="Export Key", command=self.export_key_cb).pack(**button_pack_args)

        Button(right_frame, text="Load Key", command=self.load_key_cb).pack(**button_pack_args)

        Button(left_frame, text="New Random Key", command=self.new_random_key_cb).pack(**button_pack_args)

        Button(right_frame, text="New Key From Password", command=self.key_from_pass_cb).pack(**button_pack_args)

        Button(left_frame, text="Change App Password", command=self.change_usr_pass_cb).pack(**button_pack_args)

        Button(right_frame, text="Edit Key", command=self.edit_key_cb).pack(**button_pack_args)

    def display_keys(self) -> None:

        start_index = self.page * MainWindowC.__KEYS_PER_PAGE
        if start_index > len(self.keys):
            self.page -= 1
            return
        if start_index < 0:
            self.page += 1
            return
        end_index = start_index + MainWindowC.__KEYS_PER_PAGE

        clear_window(self.key_frame)

        Label(self.key_frame, text="#", bg=self.key_frame["background"]).grid(column=1, row=0)
        Label(self.key_frame, text="NAME", bg=self.key_frame["background"]).grid(column=2, row=0)
        Label(self.key_frame, text="DESCRIPTION", bg=self.key_frame["background"]).grid(column=3, row=0)
        Label(self.key_frame, text="KEY", bg=self.key_frame["background"]).grid(column=4, row=0)

        # Draw Each key
        for index, key in enumerate(self.keys[start_index:end_index], start=start_index):
            idx = index - start_index
            # Selector
            Radiobutton(self.key_frame, bg=self.key_frame["background"], variable=self.key_choice, value=index).grid(
                column=0,
                row=idx + 2)

            Label(self.key_frame, text=str(index + 1), bg=self.key_frame["background"]).grid(column=1, row=idx + 2,
                                                                                             padx=5,
                                                                                             sticky="nesw")  # Number
            Label(self.key_frame, text=key.name, bg=self.key_frame["background"]).grid(column=2, row=idx + 2, padx=5,
                                                                                       sticky="nesw")  # Name
            Label(self.key_frame, text=key.description, bg=self.key_frame["background"]).grid(column=3, row=idx + 2,
                                                                                              padx=5,
                                                                                              sticky="nesw")  # DESCRIPTION
            if idx == 0:
                Label(self.key_frame, text=('*' * 44), bg=self.key_frame["background"]).grid(column=4, row=idx + 2,
                                                                                             padx=5,
                                                                                             sticky="nesw")
            else:
                if isinstance(key.fernetKey, bytes):
                    txt = str(key.fernetKey)[2:-1]
                else:
                    txt = str(key.fernetKey._encryption_key)[2:-1]
                Label(self.key_frame, text=txt, bg=self.key_frame["background"]).grid(column=4,
                                                                                      row=idx + 2,
                                                                                      padx=5,
                                                                                      sticky="nesw")  # Actual Key

        def change_page(amount):
            self.page += amount
            self.display_keys()

        # Buttons to navigate the pages
        button_frame = Frame(self.key_frame, bg=self.key_frame["background"])
        button_frame.grid(column=0, row=100, columnspan=5, sticky="nesw")

        right_button_image = pil_image_to_tkinter_image(ARROW_IMG)
        page_right_button = Button(button_frame, command=lambda: change_page(1), image=right_button_image)
        page_right_button.image = right_button_image
        page_right_button.pack(side=RIGHT)

        tmp = ImageOps.mirror(ARROW_IMG)
        left_button_image = pil_image_to_tkinter_image(tmp)
        page_left_button = Button(button_frame, command=lambda: change_page(-1), image=left_button_image)
        page_left_button.image = left_button_image
        page_left_button.pack(side=LEFT)

