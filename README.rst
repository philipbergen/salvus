=========
SALVUS
=========

In-memory credential store with yubikey authorization.

Stores a set of ID and VALUE for each KEY. Usually ID is the username
and VALUE is the password. Neither field may contain newlines.

-----------------------
Command line interface
-----------------------

Usage::

    salvus serve [daemon] [-p PORT] [-e EXPIRY]
    salvus auth [-p PORT]
    salvus get <KEY> [-a] [-p PORT]
    salvus set <KEY> <ID> [-a] [-p PORT]
    salvus list [-a] [-p PORT]
    salvus kill [-p PORT]
    salvus ping [-p PORT]
    salvus -h


Options:

-h, --help  This help
-p PORT     Port to listen to (always on localhost) [default: 59999]
-e EXPIRY   Auth expiry in seconds, if 0 then ``get``, ``set``
             and ``list`` requires -a [default: 3600]
-a          Add auth to each command, so requires yubikey OTP


------------------------
Interpreting the output
------------------------

All errors are printed on stderr and the exit code will be non-zero.

If exit code is zero, the output will either be blank or in the case
of ``get`` two lines, first the ID and second the secret.

When yubikey OTP (one time password) is needed, the prompt is output
on stderr, so it can be separated from the desired output.

--------------
Examples
--------------

Starting the server::

    salvus server

Enter a recognition phrase used to identify that this is the server
you trust.

Touch the yubikey and the server starts on the default port.

Setting a credential::

    salvus set github philipbergen

You will be prompted on stdout to enter the secret, press enter when
you are done.

Getting a credential::

    salvus get github

First line in the output on stdout is the ID (username) and the second
is the secret (password).

If you have set up zero expiry (auth on each request), then you need
to add ``-a`` to each call to ``get``, ``set`` or ``list``. In the
case of ``get``, you can separate prompts from results easily, since
results are the only thing on stdout::

    salvus get github -a > userpass

That will output ``Please touch the yubikey:`` on stderr, and the file
userpass will contain two lines, the first is the username and the
second line is password.

Killing the server::

    salvus kill

This obviously requires yubikey OTP.

Pinging the server::

    salvus ping

Never needs yubikey OTP. The only relevant output is the exit code,
zero for server running, non-zero (and a reason on stderr) for connect
failed.
