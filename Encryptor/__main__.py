"""Entry point of the program"""
import platform
from tkinter import Tk

from login_prompt import LoginScreen

if platform.system() == "Windows":
    import ctypes

    ctypes.windll.shcore.SetProcessDpiAwareness(1)


def main() -> None:
    """App Entry Point"""
    tk_window: Tk = Tk()
    tk_window.resizable(False, False)
    LoginScreen(tk_window).draw()
    tk_window.mainloop()


if __name__ == "__main__":
    main()
