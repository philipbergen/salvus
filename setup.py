from setuptools import setup

setup(
    name = "salvus",
    version = "0.1.13",
    packages = ['salvus'],
    package_data = {
        'salvus': ['*.rst'],
    },
    author = "philipbergen",
    author_email = "philipbergen at gmail com",
    url = 'https://github.com/philipbergen/salvus',
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
    classifiers=["Development Status :: 5 - Production/Stable",
                 "Environment :: Console",
                 "Intended Audience :: Developers",
                 "License :: OSI Approved :: MIT License",
                 "Operating System :: MacOS :: MacOS X",
                 "Operating System :: POSIX :: Linux",
                 "Programming Language :: Python",
                 "Programming Language :: Python :: 2.7",
                 "Topic :: Software Development"],
)

