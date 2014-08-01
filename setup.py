from setuptools import setup

setup(
    name = "salvus",
    version = "0.1.1",
    py_modules = ['salvus'],
    author = "philipbergen",
    author_email = "philipbergen at gmail com",
    description = "In-memory credential store with yubikey auth",
    long_description=open('README.rst').read(),
    license = "MIT",
    keywords = "yubikey auth",
    install_requires=[
        "yubikey>=0.2",
        "docopt>=0.6",
    ],
)

