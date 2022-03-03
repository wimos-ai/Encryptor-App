# cython: language_level=3
import ctypes
from tkinter import *

from loginPrompt import login_screen


def main():
    # Fixes Tkinter Blurriness
    ctypes.windll.shcore.SetProcessDpiAwareness(1)

    # window
    tkWindow = Tk()
    tkWindow.resizable(False, False)
    login_screen(tkWindow)


if __name__ == "__main__":
    main()
