import math
import os

import PIL.Image
from PIL import ImageTk


def pil_image_to_tkinter_image(image: PIL.Image.Image):
    return ImageTk.PhotoImage(image)


def quitHandler(window):
    window.destroy()
    os._exit(0)


def fileGuard(file,main_file):
    if os.path.abspath(file) == os.path.abspath(main_file):
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


def clearWindow(window):
    for widget in window.winfo_children():
        widget.destroy()


def centerWindow(root):
    root.eval('tk::PlaceWindow . center')