"""Single-source package version"""
import os


def set_version(version: str):

    global __version__                            # Declare
    __version__ = version                         # Set Global
    os.environ["PYUMBRAL_VERISON"] = __version__  # Set Env Var


if __name__ == "__main__":
    version = "0.1.0-alpha"
    set_version(version)
