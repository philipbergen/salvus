from setuptools import setup

setup(
    name = "salvus",
    version = "0.1",
    py_modules = ['salvus'],
    author = "philipbergen",
    author_email = "philipbergen at gmail com",
    description = "In-memory credential store with yubikey auth",
    license = "MIT",
    keywords = "yubikey auth",
    install_requires=[
        "yubikey>=0.2",
        "docopt>=0.6",
    ],
)

