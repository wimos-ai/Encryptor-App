import os
import sys
from tkinter import Tk, Toplevel, Frame, LabelFrame

import PIL.Image
from PIL import ImageTk


def pil_image_to_tkinter_image(image: PIL.Image.Image):
    return ImageTk.PhotoImage(image)


def quit_handler(window):
    window.destroy()
    sys.exit(0)


def file_guard(file, main_file) -> bool:
    if os.path.abspath(file) == os.path.abspath(main_file):
        return True
    return False


def clear_window(root: Tk | Toplevel | Frame | LabelFrame):
    for widget in root.winfo_children():
        widget.destroy()


def center_window(root):
    root.eval('tk::PlaceWindow . center')
