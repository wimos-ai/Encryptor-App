"""Misc Utilities"""
import os
import sys
from tkinter import Tk, Toplevel, Frame, LabelFrame

import PIL.Image
from PIL import ImageTk


def pil_image_to_tkinter_image(image: PIL.Image.Image) -> ImageTk.PhotoImage:
    """Converts a PIL.Image to a tkinter compatable image"""
    return ImageTk.PhotoImage(image)


def quit_handler(window: Tk | Toplevel) -> None:
    """Generic exit handler"""
    window.withdraw()
    window.destroy()
    sys.exit(0)


def is_same_file(file1: str, file_2: str) -> bool:
    """Checks if the two files are the same file"""
    return os.path.abspath(file1) == os.path.abspath(file_2)


def clear_window(root: Tk | Toplevel | Frame | LabelFrame) -> None:
    """Clears a tkinter window or frame"""
    for widget in root.winfo_children():
        widget.destroy()


def center_window(root: Tk) -> None:
    """Centers a Tkinter window"""
    root.eval('tk::PlaceWindow . center')
