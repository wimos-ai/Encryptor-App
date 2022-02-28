import pickle
import tkinter.messagebox as mb
from tkinter import *
from tkinter.filedialog import askopenfilename, asksaveasfilename

from PIL import ImageTk, ImageOps
from cryptography.fernet import InvalidToken

from Encryptor import Encryptor
from Encryptor.InternalKey import dumpKeys, InternalKey, loadKeys
from Encryptor.utils import fileGuard, clearWindow, pil_image_to_tkinter_image, to2DArray
from images import TrashCanImg, LockImg, ArrowImg

page: int = 0
KEY_CHOICE: IntVar = None
KEYS: list[InternalKey] = []
WINDOW: Tk = None
MAINFILE: str = ""
USERKEY: str = ""


# ######################################################################################################################
# Options Buttons
def EncryptFileButton() -> None:
    global MAINFILE

    file: str = askopenfilename()

    root = Toplevel()
    root.withdraw()
    if fileGuard(file, MAINFILE):
        mb.showerror(title="Encryption Error", message="Cannot Do Encryption Methods on Login File")
        return
    try:
        Encryptor.encrypt_file(file, KEYS[KEY_CHOICE.get()].fernetKey)
    except FileNotFoundError:
        mb.showerror(title="Encryption Error", message="Failed to get file from user")
        return
    mb.showinfo(title="Encryption Status", message=f"Successfully Encrypted {file}")


def DecryptFileButton() -> None:
    global MAINFILE
    file = askopenfilename()

    root = Toplevel()
    root.withdraw()

    if fileGuard(file, MAINFILE):
        mb.showerror(title="Encryption Error", message="Cannot Do Encryption Methods on Login File")
        return

    for key in KEYS:
        try:
            Encryptor.decrypt_file(file, key.fernetKey)
            mb.showinfo(title="Decryption Status", message=f"Decryption of file {file} Successful with key: {key.name}")
            return
        except InvalidToken:
            continue
        except FileNotFoundError:
            mb.showerror(title="Decryption Error", message=f"Failed to open file: {file}")
            return
    mb.showerror(title="Decryption Error", message=f"Decryption of {file} Unsuccessful!")


def ExportKeyButton() -> None:
    if KEY_CHOICE.get() == 0:
        mb.showerror(title="Export Error", message="Cannot Export Default Key")
        return
    else:
        file = asksaveasfilename(defaultextension=".key", filetypes=(("key file", "*.key"), ("All Files", "*.*")))
        root = Toplevel()
        root.withdraw()
        try:
            with open(file, 'wb') as usrFile:
                usrFile.write(
                    Encryptor.encrypt_data(pickle.dumps(KEYS[KEY_CHOICE.get()], protocol=pickle.HIGHEST_PROTOCOL),
                                           Encryptor.create_key(password='0')))
        except Exception:
            mb.showerror(title="Export Error", message="Generic Error")


def LoadKeyButton() -> None:
    global KEYS, WINDOW, MAINFILE, USERKEY, KEY_CHOICE
    file = askopenfilename()
    if file != '':
        try:
            with open(file, 'rb') as usrFile:
                contents = usrFile.read()
        except FileNotFoundError:
            mb.showerror(title="Key Load Error", message=f"File: {file} not found")
        KEYS.append(pickle.loads(Encryptor.decrypt_data(contents, Encryptor.create_key(password='0'))))
        dumpKeys(MAINFILE, KEYS, USERKEY)
        reloadWindow()


def NewRandomKeyButton() -> None:
    popup = Toplevel()
    popup.iconphoto(False, pil_image_to_tkinter_image(LockImg))
    popup.protocol("WM_DELETE_WINDOW", popup.destroy)

    # username label and text entry box
    Label(popup, text="Key Name").grid(row=0, column=0, padx=10, pady=10)
    name_in = StringVar(popup)
    Entry(popup, textvariable=name_in).grid(row=0, column=1, padx=1, pady=10)

    # password Description and Description entry box
    Label(popup, text="Key Description").grid(row=1, column=0, padx=10, pady=1)
    description_in = StringVar(popup)
    Entry(popup, textvariable=description_in).grid(row=1, column=1, padx=10, pady=1)

    def confirmKey(winIn, nameIn, descriptionIn, key):
        if key is None:
            key = Encryptor.create_key()
        KEYS.append(InternalKey(key, nameIn.get(), descriptionIn.get()))
        dumpKeys(MAINFILE, KEYS, USERKEY)
        reloadWindow()
        winIn.destroy()

    Button(popup, text="Confirm",
           command=lambda: confirmKey(popup, name_in, description_in, None)).grid(row=2, column=1, padx=1, pady=1)


def KeyFromPasswordButton() -> None:
    popup = Toplevel()
    popup.iconphoto(False, pil_image_to_tkinter_image(LockImg))
    popup.protocol("WM_DELETE_WINDOW", popup.destroy)

    # username label and text entry box
    Label(popup, text="Key Name").grid(row=0, column=0, padx=10, pady=10)
    name_in = StringVar(popup)
    Entry(popup, textvariable=name_in).grid(row=0, column=1, padx=1, pady=10)

    # Description label and Description entry box
    Label(popup, text="Key Description").grid(row=1, column=0, padx=10, pady=1)
    description_in = StringVar(popup)
    Entry(popup, textvariable=description_in).grid(row=1, column=1, padx=10, pady=1)

    Label(popup, text="Password").grid(row=2, column=0, padx=10, pady=1)
    password = StringVar(popup)
    Entry(popup, textvariable=password).grid(row=2, column=1, padx=10, pady=1)

    def confirmKey2(winIn, nameIn, descriptionIn, key2):
        key = Encryptor.create_key(password=key2.get())
        KEYS.append(InternalKey(key, nameIn.get(), descriptionIn.get()))
        dumpKeys(MAINFILE, KEYS, USERKEY)
        reloadWindow()
        winIn.destroy()

    Button(popup, text="Confirm",
           command=lambda: confirmKey2(popup, name_in, description_in, password)).grid(row=3, column=1, padx=1, pady=1)


def ChangeAppPasswordButton() -> None:
    popup = Toplevel()
    popup.iconphoto(False, pil_image_to_tkinter_image(LockImg))
    popup.protocol("WM_DELETE_WINDOW", popup.destroy)

    # username label and text entry box
    Label(popup, text="New Password").grid(row=0, column=0, padx=10, pady=10)
    pass_in = StringVar(popup)
    Entry(popup, textvariable=pass_in).grid(row=0, column=1, padx=1, pady=10)

    # Description label and Description entry box
    Label(popup, text="Confirm New Password").grid(row=1, column=0, padx=10, pady=1)
    pass_in_two = StringVar(popup)
    Entry(popup, textvariable=pass_in_two).grid(row=1, column=1, padx=10, pady=1)

    def change_app_pass_confirm(winIn, pass1, pass2):
        global KEYS, WINDOW, MAINFILE, USERKEY, KEY_CHOICE
        password_one = pass1.get()
        password_two = pass2.get()
        if pass1.get() == pass2.get():
            KEYS[0].fernetKey = Encryptor.create_key(password=pass2.get())
            USERKEY = KEYS[0].fernetKey
            dumpKeys(MAINFILE, KEYS, USERKEY)
            reloadWindow()
            winIn.destroy()
        elif password_one != password_two:
            mb.showerror(title="Password Change Error", message="Passwords do not match")

        elif len(password_one) <= 3:
            mb.showerror(title="Password Change Error", message="Passwords must be four characters or more")

        else:
            mb.showerror(title="Password Change Error", message="Generic Failure")

    Button(popup, text="Confirm",
           command=lambda: change_app_pass_confirm(popup, pass_in, pass_in_two)).grid(row=3, column=1, padx=1, pady=1)


def EditKeyButton() -> None:
    editingKeySpot = int(KEY_CHOICE.get())
    if editingKeySpot == 0:
        mb.showerror(title="Key Edit Error", message="Cannot Edit Default Key")
        return
    popup = Toplevel()
    popup.iconphoto(False, pil_image_to_tkinter_image(LockImg))
    popup.protocol("WM_DELETE_WINDOW", popup.destroy)
    popup.lift()
    popup.attributes("-topmost", True)
    popup.after(1, lambda: popup.focus_force)

    Label(popup, text="Edit Name").grid(row=0, column=0, padx=10, pady=10)

    nameEdit = StringVar(popup)
    nameEdit.set(KEYS[editingKeySpot].name)
    Entry(popup, textvariable=nameEdit).grid(row=0, column=1, padx=1, pady=10)

    # Description label and Description entry box
    Label(popup, text="Edit Description").grid(row=1, column=0, padx=10, pady=1)

    descriptionEdit = StringVar(popup)
    descriptionEdit.set(KEYS[editingKeySpot].description)
    Entry(popup, textvariable=descriptionEdit).grid(row=1, column=1, padx=10, pady=1)

    def deleteButtonCommand():
        KEYS.remove(KEYS[editingKeySpot])
        dumpKeys(MAINFILE, KEYS, USERKEY)
        reloadWindow()
        popup.destroy()

    im = TrashCanImg
    ph = ImageTk.PhotoImage(im)

    deleteButton = Button(popup, text="Delete Key", image=ph, command=lambda: deleteButtonCommand())
    deleteButton.image = ph
    deleteButton.grid(column=2, row=0, columnspan=2, rowspan=2, sticky='NESW', padx=10, pady=10)

    def confirmButtonCommand(key_edit_spot, name: StringVar, description: StringVar):
        newName = name.get()
        newDescription = description.get()
        KEYS[key_edit_spot].name = newName
        KEYS[key_edit_spot].description = newDescription
        dumpKeys(MAINFILE, KEYS, USERKEY)
        MainWindow(WINDOW)
        popup.destroy()

    confirmButton = Button(popup, text="Confirm Changes",
                           command=lambda: confirmButtonCommand(editingKeySpot, nameEdit, descriptionEdit))
    confirmButton.grid(column=1, row=2, sticky='NESW', padx=10, pady=10)


def MainWindow(window) -> None:
    global KEYS

    clearWindow(window)

    # Init Key Display
    keyframe = LabelFrame(window, text="Keys")
    keyframe.pack(fill="both", expand="yes", padx=10, pady=10)
    keyframe.configure(bg='gray63')
    KEYS = loadKeys(MAINFILE, USERKEY)
    displayKeys(keyframe, KEYS)

    # Init Options Frame
    options_frame = LabelFrame(window, text="Options")
    options_frame.configure(bg='gray63')
    options_frame.pack(fill="both", expand=True, padx=10, pady=10, side=LEFT)
    displayOptions(options_frame, window)


def reloadWindow() -> None:
    global WINDOW
    MainWindow(WINDOW)


def displayOptions(frame, window) -> None:
    bkground = frame["background"]
    leftFrame = Frame(frame, bg=bkground)
    leftFrame.pack(side=LEFT, fill="both", expand=True)
    rightFrame = Frame(frame, bg=bkground)
    rightFrame.pack(side=RIGHT, fill="both", expand=True)

    b1 = Button(leftFrame, text="Encrypt File", command=EncryptFileButton)
    b1.pack(fill="both", side=TOP, expand=True, padx=10, pady=3)

    b2 = Button(rightFrame, text="Decrypt File", command=DecryptFileButton)
    b2.pack(fill="both", side=TOP, expand=True, padx=10, pady=3)

    b3 = Button(leftFrame, text="Export Key", command=ExportKeyButton)
    b3.pack(fill="both", side=TOP, expand=True, padx=10, pady=3)

    b4 = Button(rightFrame, text="Load Key", command=LoadKeyButton)
    b4.pack(fill="both", side=TOP, expand=True, padx=10, pady=3)

    b5 = Button(leftFrame, text="New Random Key", command=NewRandomKeyButton)
    b5.pack(fill="both", side=TOP, expand=True, padx=10, pady=3)

    b6 = Button(rightFrame, text="New Key From Password", command=KeyFromPasswordButton)
    b6.pack(fill="both", side=TOP, expand=True, padx=10, pady=3)

    b7 = Button(leftFrame, text="Change App Password", command=ChangeAppPasswordButton)
    b7.pack(fill="both", side=TOP, expand=True, padx=10, pady=3)

    b8 = Button(rightFrame, text="Edit Key", command=EditKeyButton)
    b8.pack(fill="both", side=TOP, expand=True, padx=10, pady=3)


def displayKeys(frame, keys) -> None:
    global KEY_CHOICE
    global page
    background = frame["background"]
    num_header = Label(frame, text="#", bg=background)
    num_header.grid(column=1, row=0)
    name_header = Label(frame, text="NAME", bg=background)
    name_header.grid(column=2, row=0)
    descriptionHeader = Label(frame, text="DESCRIPTION", bg=background)
    descriptionHeader.grid(column=3, row=0)
    keyHeader = Label(frame, text="KEY", bg=background)
    keyHeader.grid(column=4, row=0)
    InternalKeyRegister = to2DArray(keys, int(8))
    if page > (len(InternalKeyRegister) - 1):
        page = page % len(InternalKeyRegister)

    if page < (len(InternalKeyRegister)):
        page = page % len(InternalKeyRegister)

    for x in range(0, len(InternalKeyRegister[page])):
        index = (page * len(InternalKeyRegister[page])) + x
        try:
            if type(InternalKeyRegister[page][x]) == int:
                break
        except IndexError:
            break
        # Selector
        keyButton = Radiobutton(frame, bg=background, variable=KEY_CHOICE, value=index)
        keyButton.grid(column=0, row=x + 2)

        Label(frame, text=str(index + 1), bg=background).grid(column=1, row=x + 2, padx=5, sticky="nesw")  # Number
        name = InternalKeyRegister[page][x].name
        Label(frame, text=name, bg=background).grid(column=2, row=x + 2, padx=5, sticky="nesw")  # Name
        des = InternalKeyRegister[page][x].description
        Label(frame, text=des, bg=background).grid(column=3, row=x + 2, padx=5, sticky="nesw")  # DESCRIPTION
        if index == 0:
            Label(frame, text=('*' * 44), bg=background).grid(column=4, row=x + 2, padx=5, sticky="nesw")
        else:
            if isinstance(InternalKeyRegister[page][x].fernetKey, bytes):
                txt = str(InternalKeyRegister[page][x].fernetKey)[2:-1]
            else:
                txt = str(InternalKeyRegister[page][x].fernetKey._encryption_key)[2:-1]
            Label(frame, text=txt, bg=background).grid(column=4,
                                                       row=x + 2,
                                                       padx=5,
                                                       sticky="nesw")  # Actual Key

    def changePage(amount):
        global page
        page = page + amount
        reloadWindow()

    # Buttons to navigate the pages
    buttonFrame = Frame(frame, bg=background)
    buttonFrame.grid(column=0, row=100, columnspan=5, sticky="nesw")

    rightButtonImage = pil_image_to_tkinter_image(ArrowImg)
    pageRightButton = Button(buttonFrame, command=lambda: changePage(1), image=rightButtonImage)
    pageRightButton.image = rightButtonImage
    pageRightButton.pack(side=RIGHT)

    tmp = ImageOps.mirror(ArrowImg)
    leftButtonImage = ImageTk.PhotoImage(tmp)
    pageLeftButton = Button(buttonFrame, command=lambda: changePage(-1), image=leftButtonImage)
    pageLeftButton.image = leftButtonImage
    pageLeftButton.pack(side=LEFT)


def entry_point(window, file, user_key, keys) -> None:
    global KEYS, WINDOW, MAINFILE, USERKEY, KEY_CHOICE
    KEY_CHOICE = IntVar()
    KEY_CHOICE.set(0)
    WINDOW = window
    MAINFILE = file
    USERKEY = user_key
    KEYS = keys
    MainWindow(window)
