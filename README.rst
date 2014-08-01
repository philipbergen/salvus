=========
SALVUS
=========

In-memory credential store with yubikey authorization.

Stores a set of ID and VALUE for each KEY. Usually ID is the
username and VALUE is the password.

Neither field may contain newlines.

KEY and ID may not contain colon (:).

Usage::
    salvus serve [daemon] [noauth] [-p PORT] [-e EXPIRY]
    salvus auth [-p PORT]
    salvus get <KEY> [-a]
    salvus set <KEY> <ID> <VALUE> [-a]
    salvus list [-a]

Options:
-h --help  This help
-p PORT    Port to listen to (always on localhost) [default: 5999]
-e EXPIRY  Auth expiry in seconds, if 0 then get, set and list requires -a [default: 3600]
-a         Add auth to each command, so requires yubikey OTP



Server:

When serving
