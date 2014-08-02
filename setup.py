from setuptools import setup

setup(
    name = "salvus",
    version = "0.1.8",
    packages = ['salvus'],
    package_data = {
        'salvus': ['*.rst'],
    },
    author = "philipbergen",
    author_email = "philipbergen at gmail com",
    description = "In-memory credential store with yubikey auth",
    long_description=open('README.rst').read(),
    license = 'LICENSE.txt',
    keywords = "yubikey auth",
    scripts = ['bin/salvus'],
    install_requires=[
        "yubikey>=0.2",
        "docopt>=0.6",
        "daemonize>=2.2",
    ],
)

