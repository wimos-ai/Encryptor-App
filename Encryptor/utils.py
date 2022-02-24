import PIL.Image
from PIL import ImageTk


def pil_image_to_tkinter_image(image: PIL.Image.Image):
    return ImageTk.PhotoImage(image)
