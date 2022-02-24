import ast
import os
import pickle
from tkinter.filedialog import askopenfilename

from cryptography.fernet import InvalidToken

from fernetEncryption import Encryptor


class InternalKey():
    def __init__(self, fernetKey, name, description):
        self.fernetKey = fernetKey
        self.name = name
        self.description = description

    def toStr(self):
        return (str(self.__dict__))

    def fromStr(string):
        tmp = InternalKey(None, None, None)
        tmp.__dict__ = ast.literal_eval(string)
        return tmp


def fileExist(file):
    try:
        f = open(file, 'r')
        f.close()
        return True
    except:
        return False


def clear():
    # check and make call for specific operating system 
    if os.name == 'nt':
        os.system('cls')

        # for mac and linux(here, os.name is 'posix')
    else:
        os.system('clear')


def stringToLength(string, length):
    if len(string) == length:
        return string
    if len(string) > length:
        return string[:length]
    else:
        while len(string) < length:
            string = string + ' '
        return string


def displayKeys(Keys):
    HEADER = '   '"     NAME     " + "                    description                    " + "                      KEY                      "
    print(HEADER)
    print(
        '----------------------------------------------------------------------------------------------------------------------------')
    x = 1
    for key in Keys:
        # Prints line number and name
        print(str(x) + ' | ' + stringToLength(key.name, len("     NAME     ")), end=' | ')
        print(stringToLength(key.description, len("                    description                    ")), end=' | ')
        if x == 1:
            print(stringToLength("********************************************",
                                 len("                      KEY                      ")), end=' | \n')
        else:
            print(stringToLength(str(key.fernetKey)[2:-1], len("                      KEY                      ")),
                  end=' | \n')
        x = x + 1
    print(
        '----------------------------------------------------------------------------------------------------------------------------')


def dumpKeys(file, keys, encryptionKey):
    encPickle = Encryptor.encrypt_data(pickle.dumps(keys, protocol=pickle.HIGHEST_PROTOCOL), encryptionKey)
    with open(file, 'wb') as File:
        File.write(encPickle)


def loadKeys(file, decryptionKey):
    with open(file, 'rb') as File:
        contents = File.read()
    return pickle.loads(Encryptor.decrypt_data(contents, decryptionKey))


Encryptor = Encryptor()
MAINFILE = "main.db"
# MAINFILE SPECS
"""
Main file is a file of an encrypted pickle object
Encrypted using Fernet Key

Decode MAINFILE by decrypting to string
depickle string and save as KEYS array

"""


def main():
    global name, description
    if fileExist(MAINFILE):
        while (True):
            # Generates key from user password
            USERKEY = Encryptor.create_key(password=str(input("Please Enter your password: ")))
            try:
                # Opens and decrypts db file
                with open(MAINFILE, 'rb') as f:
                    mainContents = Encryptor.decrypt_data(f.read(), USERKEY, 's')
                    break
            except InvalidToken:
                print("Incorrect Password")

    else:
        # Initialize workspace for new user
        # Develop Password and Key
        clear()
        print("No previous session found.")
        while True:
            newPass = str(input("Please input a password for new session: "))
            newPass2 = str(input("Please confirm password: "))
            if newPass == newPass2:
                if len(newPass2) >= 4:
                    USERKEY = Encryptor.create_key(password=newPass)
                    # print(USERKEY)
                    break
                else:
                    clear()
                    print("Password must be at least 4 charecters")
                    continue
            else:
                clear()
                print("Passwords do not match")
        # init MAINFILE
        KEYS = []
        writeKey = InternalKey(USERKEY, "Password Key", "The Key Generated from your password")
        KEYS.append(writeKey)
        dumpKeys(MAINFILE, KEYS, USERKEY)
    # Start Main Loop
    OPTIONS = "________________OPTIONS:________________\n1: Encrypt File\n2: Decrypt File\n3: Export Key\n4: Load Key\n5: New Random Key\n6: New Key From Password\n7: Change Password\n8: Exit"
    ERROR_MSG = "Password Protected Session Created"
    KEYS = loadKeys(MAINFILE, USERKEY)
    while True:
        clear()
        KEYS = loadKeys(MAINFILE, USERKEY)

        displayKeys(KEYS)
        if ERROR_MSG is None:
            print("System Message: Nothing to Report")
        if ERROR_MSG is not None:
            print("System Message: " + str(ERROR_MSG))
            ERROR_MSG = None

        print(OPTIONS)
        # Get User Choice
        try:
            choice = int(input("--->"))
            if choice > len(OPTIONS.split('\n')) - 1:
                optionsNum = len(OPTIONS.split('\n')) - 1
                ERROR_MSG = "Invalid Choice\nOnly " + str(optionsNum) + ' options'
                continue
        except ValueError:
            ERROR_MSG = "Invalid Input"
            continue
        # Encrypt File
        if choice == 1:
            try:
                keyChoice = int(input("Which Key Number would you like to use?"))
            except ValueError:
                ERROR_MSG = "Invalid Input"
                continue
            print("Choose File in GUI window")
            file = askopenfilename()
            try:
                Encryptor.encrypt_file(file, KEYS[keyChoice - 1].fernetKey)
            except:
                ERROR_MSG = "Encryption Error!"
            ERROR_MSG = "Encryption Success!"
            continue
        # Decrypt File by itterating through all keys
        if choice == 2:
            print("Choose File in GUI window")
            file = askopenfilename()
            decryptionSuccess = False
            for key in KEYS:
                try:
                    Encryptor.decrypt_file(file, key.fernetKey)
                    ERROR_MSG = "Decryption Successfull with key: " + key.name
                    decryptionSuccess = True
                    break
                except InvalidToken:
                    continue
            if decryptionSuccess == False:
                ERROR_MSG = "Decryption Unsuccessfull!"
            continue
        # Export Key
        if choice == 3:
            try:
                keyChoice = int(input("Choose Key To Export: "))
                if keyChoice == 1:
                    ERROR_MSG = "Cannot Dump Password Key"
                    continue
                keyToDump = KEYS[keyChoice - 1]
            except Exception:
                ERROR_MSG = "Invalid Choice!"
                continue
            try:
                with open(keyToDump.name + '.key', 'w') as file:
                    file.write(keyToDump.toStr())
            except Exception:
                ERROR_MSG = "Error Writing to File"
                continue
        # Load Key
        if choice == 4:
            print("Choose File in GUI window")
            file = askopenfilename()
            try:
                with open(file, 'r') as file:
                    KEYS.append(InternalKey.fromStr(file.read()))
            except ValueError:
                ERROR_MSG = "Invalid File Contents"
                continue
            except UnicodeDecodeError:
                ERROR_MSG = "Corrupt File"
                continue
            dumpKeys(MAINFILE, KEYS, USERKEY)
            ERROR_MSG = "Load Success"
        # New Random Key
        if choice == 5:
            try:
                name = str(input("Input Key Name: "))
                description = str(input("Input Key Description: "))
                key = Encryptor.create_key()
            except Exception:
                ERROR_MSG = "Invalid Input"
                continue
            KEYS.append(InternalKey(key, name, description))
            ERROR_MSG = "New Key Success"
            dumpKeys(MAINFILE, KEYS, USERKEY)
            continue
        # New Key From Password
        if choice == 6:
            try:
                name = str(input("Input Key Name: "))
                description = str(input("Input Key Description: "))
                pW = str(input("Input Password to Use: "))
            except:
                ERROR_MSG = "Invalid Input"
                continue
            ERROR_MSG = "New Key Success"
            key = Encryptor.create_key(password=pW)
            KEYS.append(InternalKey(key, name, description))
            dumpKeys(MAINFILE, KEYS, USERKEY)
        # change app password
        if choice == 7:
            try:
                choice = str(input("Would you like to change your password? If so, enter YES\n-->"))
                if choice == "YES":
                    newPass = str(input("Input New Pasword: "))
                    newPass2 = str(input("Confirm New Pasword: "))
                if len(newPass) < 4:
                    ERROR_MSG = "New Password Must be 4 or more charecters"
                    continue
            except Exception:
                ERROR_MSG = "Invalid Input"
                continue

            if newPass == newPass2:
                USERKEY = Encryptor.create_key(password=newPass)
                KEYS[0].fernetKey = USERKEY
                dumpKeys(MAINFILE, KEYS, USERKEY)
                continue
        # Exit
        if choice == 8:
            dumpKeys(MAINFILE, KEYS, USERKEY)
            break


# Start Main user session if launched from w/o args
if __name__ == "__main__":
    main()
