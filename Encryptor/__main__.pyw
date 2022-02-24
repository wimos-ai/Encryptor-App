# cython: language_level=3
import ctypes
import math
import os
import pickle
from tkinter import *
from tkinter.filedialog import askopenfilename, asksaveasfilename

from PIL import ImageTk, ImageOps
from cryptography.fernet import InvalidToken

import utils
from InternalKey import InternalKey, dumpKeys, loadKeys
from fernetEncryption import Encryptor

from images import *


# Util Methods
def quitHandler(window):
    window.destroy()
    os._exit(0)


def fileGuard(file):
    if os.path.abspath(file) == os.path.abspath(MAINFILE):
        return True


def to2DArray(List, rowSize):
    InternalList = []
    for x in range(0, (math.ceil(len(List) / rowSize))):
        InternalList.append([])
    for x in range(0, len(InternalList)):
        for y in range(0, rowSize):
            InternalList[x].append(0)
    for x in range(0, len(List)):
        InternalList[math.floor(x / rowSize)][x % rowSize] = List[x]

    return InternalList


# ######################################################################################################################
# GUI Methods
def loginMessage(message):
    global infoLabelMessage
    infoLabelMessage.set(message)


def createUser(usernameIn, p1In, p2In):
    global USERKEY  # FERNET KEY OF THE USER
    global KEYS  # KEYS THE USER HAS LOADED
    global MAINFILE  # THE FILE TO THE USER KEYS DATABASE FILE
    p1 = p1In.get()
    p2 = p2In.get()
    username = usernameIn.get()
    if p1 == p2 and len(p1) > 3:
        USERKEY = Encryptor.create_key(password=p1)
        writeKey = InternalKey(USERKEY, "Password Key", "The Key Generated from your password")
        KEYS = [writeKey]
        MAINFILE = username + '.db'
        dumpKeys(MAINFILE, KEYS, USERKEY)
        loginWin.destroy()
        tkWindow.destroy()


def returnToLogin():
    tkWindow.deiconify()
    loginWin.withdraw()
    loginWin.destroy()


def validateLogin(username, Password):
    password = Password.get()
    username = username.get()
    global USERKEY  # FERNET KEY OF THE USER
    global KEYS  # KEYS THE USER HAS LOADED
    global MAINFILE  # THE FILE TO THE USER KEYS DATABASE FILE
    try:
        USERKEY = Encryptor.create_key(password=password)
        MAINFILE = username + '.db'
        KEYS = loadKeys(MAINFILE, USERKEY)
        loginMessage("Success")
        tkWindow.destroy()
    except FileNotFoundError:
        USERKEY = None
        KEYS = None
        MAINFILE = None
        loginMessage("User not found")
    except InvalidToken:
        USERKEY = None
        KEYS = None
        MAINFILE = None
        loginMessage("Login Failed")


def newLogin(tkWindow):
    tkWindow.withdraw()
    global loginWin
    loginWin = Toplevel()
    # loginWin.geometry('400x150')
    loginWin.title('New User')
    loginWin.protocol("WM_DELETE_WINDOW", lambda: quitHandler(loginWin))

    # User Row
    Label(loginWin, text="User Name").grid(row=0, column=0)
    newUserName = StringVar(loginWin)
    Entry(loginWin, textvariable=newUserName).grid(row=0, column=1)

    # Password Row 1
    Label(loginWin, text="Password").grid(row=1, column=0)
    newPass1 = StringVar(loginWin)
    Entry(loginWin, textvariable=newPass1).grid(row=1, column=1)

    # Password Row 2
    Label(loginWin, text="Confirm Password").grid(row=2, column=0)
    newPass2 = StringVar(loginWin)
    Entry(loginWin, textvariable=newPass2).grid(row=2, column=1)

    # Create User Button
    Button(loginWin, text='Create New User',
           command=lambda: createUser(newUserName, newPass1, newPass2)).grid(row=3, column=2, padx=10,
                                                                             pady=10)

    # Return To Login Screen Button
    Button(loginWin, text='Return To Login', command=returnToLogin).grid(row=3, column=0, padx=10,
                                                                         pady=10)

    # User Message
    msgTxt = StringVar(loginWin)
    msgTxt.set("Enter Username and Password")
    Label(loginWin, textvariable=msgTxt).grid(row=3, column=1)
    loginWin.mainloop()


def displayKeys(frame, KEYS):
    global keyChoice
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
    InternalKeyRegister = to2DArray(KEYS, int(8))
    if page > (len(InternalKeyRegister) - 1):
        page = page % len(InternalKeyRegister)

    for x in range(0, len(InternalKeyRegister[page])):
        index = (page * len(InternalKeyRegister[page])) + x
        try:
            if type(InternalKeyRegister[page][x]) == int:
                break
        except IndexError:
            break
        # Selector
        keyButton = Radiobutton(frame, bg=background, variable=keyChoice, value=index)
        keyButton.grid(column=0, row=x + 2)

        Label(frame, text=str(index + 1), bg=background).grid(column=1, row=x + 2, padx=5, sticky="nesw")  # Number
        name = InternalKeyRegister[page][x].name
        Label(frame, text=name, bg=background).grid(column=2, row=x + 2, padx=5, sticky="nesw")  # Name
        des = InternalKeyRegister[page][x].description
        Label(frame, text=des, bg=background).grid(column=3, row=x + 2, padx=5, sticky="nesw")  # DESCRIPTION
        if index == 0:
            Label(frame, text=('*' * 44), bg=background).grid(column=4, row=x + 2, padx=5, sticky="nesw")
        else:
            Label(frame, text=str(InternalKeyRegister[page][x].fernetKey)[2:-1], bg=background).grid(column=4,
                                                                                                     row=x + 2, padx=5,
                                                                                                     sticky="nesw")  # Actual Key

    def changePage(amount):
        global page
        page = page + amount
        global win
        reloadWindow(win)

    # Buttons to navigate the pages
    buttonFrame = Frame(frame, bg=background)
    buttonFrame.grid(column=0, row=100, columnspan=5, sticky="nesw")

    rightButtonImage = utils.pil_image_to_tkinter_image(ArrowImg)
    pageRightButton = Button(buttonFrame, command=lambda: changePage(1), image=rightButtonImage)
    pageRightButton.image = rightButtonImage
    pageRightButton.pack(side=RIGHT)

    tmp = ImageOps.mirror(ArrowImg)
    leftButtonImage = ImageTk.PhotoImage(tmp)
    pageLeftButton = Button(buttonFrame, command=lambda: changePage(-1), image=leftButtonImage)
    pageLeftButton.image = leftButtonImage
    pageLeftButton.pack(side=LEFT)


# ######################################################################################################################
# Options Buttons
def EncryptFileButton():
    try:
        file = askopenfilename()
    except Exception:
        return
    root = Toplevel()
    root.withdraw()
    if fileGuard(file):
        sysMsgStr.set(f"Cannot Do Encryption Methods on Login File")
        return
    try:
        Encryptor.encrypt_file(file, KEYS[keyChoice.get()].fernetKey)
    except FileNotFoundError:
        sysMsgStr.set(f"Failed to get file from user")
    sysMsgStr.set(f"Successfully Encrypted {file}")


def DecryptFileButton():
    try:
        file = askopenfilename()
    except Exception:
        return
    # NOTE: These withdrawn files will leak memory
    # Thankfully, they are freed on app exit
    root = Toplevel()
    root.withdraw()
    if fileGuard(file):
        sysMsgStr.set(f"Cannot Do Encryption Methods on Login File")
        return
    decryptionSuccess = False
    decryptSuccessString = ''
    for key in KEYS:
        try:
            Encryptor.decrypt_file(file, key.fernetKey)
            decryptSuccessString = f"Decryption of file {file} Successful with key: " + key.name
            decryptionSuccess = True
            break
        except InvalidToken:
            continue
        except FileNotFoundError:
            sysMsgStr.set(f"Failed to open file")
            return
    if not decryptionSuccess:
        sysMsgStr.set(f"Decryption of {file} Unsuccessful!")
    else:
        sysMsgStr.set(f"{decryptSuccessString}")


def ExportKeyButton():
    if keyChoice.get() == 0:
        sysMsgStr.set("Cannot Export Password Key")
    else:
        file = asksaveasfilename(defaultextension=".key", filetypes=(("key file", "*.key"), ("All Files", "*.*")))
        root = Toplevel()
        root.withdraw()
        with open(file, 'wb') as usrFile:
            usrFile.write(Encryptor.encrypt_data(pickle.dumps(KEYS[keyChoice.get()], protocol=pickle.HIGHEST_PROTOCOL),
                                                 Encryptor.create_key(password='0')))


def LoadKeyButton():
    global win
    global USERKEY  # FERNET KEY OF THE USER
    global KEYS  # KEYS THE USER HAS LOADED
    global MAINFILE  # THE FILE TO THE USER KEYS DATABASE FILE
    file = askopenfilename()
    if file != '':
        with open(file, 'rb') as usrFile:
            contents = usrFile.read()
        del file
        KEYS.append(pickle.loads(Encryptor.decrypt_data(contents, Encryptor.create_key(password='0'))))
        # (file,keys,encryptionKey)
        dumpKeys(MAINFILE, KEYS, USERKEY)
        reloadWindow(win)


def NewRandomKeyButton():
    global popup
    popup = Toplevel()
    addLockIcon(popup)
    popup.protocol("WM_DELETE_WINDOW", popup.destroy)

    # username label and text entry box
    Label(popup, text="Key Name").grid(row=0, column=0, padx=10, pady=10)
    nameIn65161 = StringVar(popup)
    Entry(popup, textvariable=nameIn65161).grid(row=0, column=1, padx=1, pady=10)

    # password Description and Description entry box
    Label(popup, text="Key Description").grid(row=1, column=0, padx=10, pady=1)
    descriptionIn64651 = StringVar(popup)
    Entry(popup, textvariable=descriptionIn64651).grid(row=1, column=1, padx=10, pady=1)

    def confirmKey(winIn, nameIn65161, descriptionIn64651, key):
        if key is None:
            key = Encryptor.create_key()
        KEYS.append(InternalKey(key, nameIn65161.get(), descriptionIn64651.get()))
        dumpKeys(MAINFILE, KEYS, USERKEY)
        reloadWindow(winIn)
        winIn.destroy()

    confirmationButton = Button(popup, text="Confirm",
                                command=lambda: confirmKey(popup, nameIn65161, descriptionIn64651, None))
    confirmationButton.grid(row=2, column=1, padx=1, pady=1)


def KeyFromPasswordButton():
    global popup2
    popup2 = Toplevel()
    addLockIcon(popup2)
    popup2.protocol("WM_DELETE_WINDOW", popup2.destroy)

    # username label and text entry box
    Label(popup2, text="Key Name").grid(row=0, column=0, padx=10, pady=10)
    nameIn65161 = StringVar(popup2)
    Entry(popup2, textvariable=nameIn65161).grid(row=0, column=1, padx=1, pady=10)

    # Description label and Description entry box
    Label(popup2, text="Key Description").grid(row=1, column=0, padx=10, pady=1)
    descriptionIn64651 = StringVar(popup2)
    Entry(popup2, textvariable=descriptionIn64651).grid(row=1, column=1, padx=10, pady=1)

    Label(popup2, text="Password").grid(row=2, column=0, padx=10, pady=1)
    password287138 = StringVar(popup2)
    Entry(popup2, textvariable=password287138).grid(row=2, column=1, padx=10, pady=1)

    def confirmKey2(winIn, nameIn65161, descriptionIn64651, key2):
        key = Encryptor.create_key(password=key2.get())
        KEYS.append(InternalKey(key, nameIn65161.get(), descriptionIn64651.get()))
        dumpKeys(MAINFILE, KEYS, USERKEY)
        reloadWindow(winIn)
        winIn.destroy()

    confirmationButton = Button(popup2, text="Confirm",
                                command=lambda: confirmKey2(popup2, nameIn65161, descriptionIn64651, password287138))
    confirmationButton.grid(row=3, column=1, padx=1, pady=1)


def ChangeAppPasswordButton():
    global popup3
    popup3 = Toplevel()
    addLockIcon(popup3)
    popup3.protocol("WM_DELETE_WINDOW", popup3.destroy)

    # username label and text entry box
    Label(popup3, text="New Password").grid(row=0, column=0, padx=10, pady=10)
    passIn1_54543 = StringVar(popup3)
    Entry(popup3, textvariable=passIn1_54543).grid(row=0, column=1, padx=1, pady=10)

    # Description label and Description entry box
    Label(popup3, text="Confirm New Password").grid(row=1, column=0, padx=10, pady=1)
    passIn2_465464 = StringVar(popup3)
    Entry(popup3, textvariable=passIn2_465464).grid(row=1, column=1, padx=10, pady=1)

    def confirmKey3(winIn, pass1, pass2):
        if pass1.get() == pass2.get():
            KEYS[0].fernetKey = Encryptor.create_key(password=pass2.get())
            global USERKEY
            USERKEY = KEYS[0].fernetKey
            dumpKeys(MAINFILE, KEYS, USERKEY)
            reloadWindow(winIn)
            winIn.destroy()

    confirmationButton = Button(popup3, text="Confirm",
                                command=lambda: confirmKey3(popup3, passIn1_54543, passIn2_465464))
    confirmationButton.grid(row=3, column=1, padx=1, pady=1)


def EditKeyButton():
    editingKeySpot = int(keyChoice.get())
    global infoLabelMessage
    if editingKeySpot == 0:
        sysMsgStr.set("Cannot Edit Default Key")
        return
    global popup4
    popup4 = Toplevel()
    addLockIcon(popup4)
    popup4.protocol("WM_DELETE_WINDOW", popup4.destroy)
    popup4.lift()
    popup4.attributes("-topmost", True)
    popup4.after(1, lambda: popup4.focus_force)

    Label(popup4, text="Edit Name").grid(row=0, column=0, padx=10, pady=10)
    global nameEdit
    nameEdit = StringVar(popup4)
    nameEdit.set(KEYS[editingKeySpot].name)
    Entry(popup4, textvariable=nameEdit).grid(row=0, column=1, padx=1, pady=10)

    # Description label and Description entry box
    Label(popup4, text="Edit Description").grid(row=1, column=0, padx=10, pady=1)
    global descriptionEdit
    descriptionEdit = StringVar(popup4)
    descriptionEdit.set(KEYS[editingKeySpot].description)
    Entry(popup4, textvariable=descriptionEdit).grid(row=1, column=1, padx=10, pady=1)

    def deleteButtonCommand():
        KEYS.remove(KEYS[editingKeySpot])
        global win
        dumpKeys(MAINFILE, KEYS, USERKEY)
        reloadWindow(win)
        popup4.destroy()

    im = TrashCanImg
    ph = ImageTk.PhotoImage(im)

    deleteButton = Button(popup4, text="Delete Key", image=ph, command=lambda: deleteButtonCommand())
    deleteButton.image = ph
    deleteButton.grid(column=2, row=0, columnspan=2, rowspan=2, sticky='NESW', padx=10, pady=10)

    def confirmButtonCommand(editingKeySpot):
        global descriptionEdit
        global nameEdit
        newName = nameEdit.get()
        newDescription = descriptionEdit.get()
        KEYS[editingKeySpot].name = newName
        KEYS[editingKeySpot].description = newDescription
        dumpKeys(MAINFILE, KEYS, USERKEY)
        reloadWindow(winIn)
        popup4.destroy()

    confirmButton = Button(popup4, text="Confirm Changes", command=lambda: confirmButtonCommand(editingKeySpot))
    confirmButton.grid(column=1, row=2, sticky='NESW', padx=10, pady=10)


# ######################################################################################################################
# Window Methods


def loadWindow(win):
    # Init Key Display
    keyframe = LabelFrame(win, text="Keys")
    keyframe.pack(fill="both", expand="yes", padx=10, pady=10)
    keyframe.configure(bg='gray63')
    KEYS = loadKeys(MAINFILE, USERKEY)
    displayKeys(keyframe, KEYS)

    # Init System Message System
    global sysMsgStr
    SysMsgFrame = LabelFrame(win, text="System Message:")
    SysMsgFrame.configure(bg="gray63")
    SysMsgFrame.pack(fill="both", expand="yes", padx=10, pady=10)
    sysMsgStr = StringVar()
    sysMsgStr.set("Nothing to report")
    sysMsg = Label(SysMsgFrame, textvariable=sysMsgStr, bg='gray63')
    sysMsg.pack(side=LEFT)

    # Init Options Frame
    optionsframe = LabelFrame(win, text="Options")
    optionsframe.configure(bg='gray63')
    optionsframe.pack(fill="both", expand=True, padx=10, pady=10, side=LEFT)
    displayOptions(optionsframe)


def reloadWindow(win):
    for widget in win.winfo_children():
        widget.destroy()
    loadWindow(win)


def displayOptions(frame):
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


def centerWindow(root):
    root.eval('tk::PlaceWindow . center')
    '''
    # Gets the requested values of the height and width.
    windowWidth = root.winfo_reqwidth()
    windowHeight = root.winfo_reqheight()
    
    # Gets both half the screen width/height and window width/height
    positionRight = int(root.winfo_screenwidth()/2 - windowWidth/2)
    positionDown = int(root.winfo_screenheight()/2 - windowHeight/2)
     
    # Positions the window in the center of the page.
    root.geometry("+{}+{}".format(positionRight, positionDown))'''


def addLockIcon(window):
    window.iconphoto(False, utils.pil_image_to_tkinter_image(LockImg))


# ######################################################################################################################

def main():
    global USERKEY  # FERNET KEY OF THE USER
    global KEYS  # KEYS THE USER HAS LOADED
    global MAINFILE  # THE FILE TO THE USER KEYS DATABASE FILE

    # Fixes Tkinter Blurriness
    ctypes.windll.shcore.SetProcessDpiAwareness(1)

    # window
    global tkWindow
    tkWindow = Tk()
    # Add Lock Icon
    tkWindow.iconphoto(False, utils.pil_image_to_tkinter_image(LockImg))

    centerWindow(tkWindow)
    tkWindow.lift()
    # tkWindow.geometry('400x150')
    tkWindow.title('Login')
    tkWindow.protocol("WM_DELETE_WINDOW", lambda: quitHandler(tkWindow))

    # username label and text entry box
    Label(tkWindow, text="User Name").grid(row=0, column=0, padx=10, pady=10)
    global username
    username = StringVar(tkWindow)
    Entry(tkWindow, textvariable=username).grid(row=0, column=1, padx=1, pady=10)

    # password label and password entry box
    Label(tkWindow, text="Password").grid(row=1, column=0, padx=10, pady=1)
    global password
    password = StringVar(tkWindow)
    Entry(tkWindow, textvariable=password, show='*').grid(row=1, column=1, padx=1, pady=1)

    # Error Message Init
    global infoLabelMessage
    infoLabelMessage = StringVar(tkWindow)
    infoLabelMessage.set("Please Login")
    infoLabel = Label(tkWindow, textvariable=infoLabelMessage)
    infoLabel.grid(row=4, column=1, padx=1, pady=10)

    # login button
    Button(tkWindow, text="Login", command=lambda: validateLogin(username, password)).grid(row=4,
                                                                                           column=0,
                                                                                           padx=10,
                                                                                           pady=10)

    # New User Button
    Button(tkWindow, text='New User', command=lambda: newLogin(tkWindow)).grid(row=4, column=2, padx=10,
                                                                               pady=10)

    tkWindow.mainloop()

    assert USERKEY != None
    assert MAINFILE != None
    assert KEYS != None

    # Init Window
    global win
    global page
    page = 0
    win = Tk()
    global keyChoice
    keyChoice = IntVar()
    keyChoice.set(0)
    addLockIcon(win)
    win.configure(bg="gray63")
    win.title("Encryptor")
    win.protocol("WM_DELETE_WINDOW", lambda: quitHandler(win))
    loadWindow(win)
    win.lift()
    win.mainloop()


if __name__ == "__main__":
    main()