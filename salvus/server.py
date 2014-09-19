import sys

def serve(port, expiry, auth, recognition, yubi_id=17627, unsafe_log=False,
          log=(sys.stdout.write, 'SALVUS SERVE: ', '\n')):
    """
    Starts a server on localhost, port :port:.

    :param port: Any valid port number
    :param expiry: Number of seconds a yubikey auth is valid before
                   expiring. Set to zero to require OTP on each command.
    :param auth: An initial yubikey OTP for establishing the yubikey owner.
    :param recognition: Personal secret phrase that establishes to you that
                        the server is the one you started.
    :param yubi_id: My (philipbergen) yubikey api id. Not sure if it matters
                    who's number is being used. Getting your own is easy, go
                    to yubikey.com.
    :param unsafe_log: Log everything, including sensitive information.
    :param log: To redirect log output somewhere else, a tuple of a method
                to call, a prefix and a postfix.
    """

    import yubikey
    import socket
    import time
    from os import getpid
    from . import sock_readline

    def split(chs):
        res = None
        tmp = []
        try:
            chs = iter(chs)
            while True:
                ch = chs.next()
                if ch == ':':
                    if res is None:
                        res = []
                    res.append(''.join(tmp))
                    tmp = []
                    continue
                if ch == '\\':
                    ch = chs.next()
                tmp.append(ch)
        except StopIteration:
            if tmp and res is None:
                res = []
            if res is not None:
                res.append(''.join(tmp))
        return res

    def verify(key):
        log(prefix + 'VERIFY ' + censor(key[:-8]) + key[-8:] + postfix)
        if not yubikey.verify(key, yubi_id):
            return 'Failed validation'
        if owner != key[:12]:
            return 'Owner mismatch'
        return None

    class Shutdown(Exception):
        "Used internally to signal shutdown"

    class Authorize(Exception):
        "Used to signal required authorization"

    class Fail(Exception):
        "Used to signal failed command"

    def censor(s, unsafe_log=unsafe_log):
        if unsafe_log:
            return s
        return ''

    prefix = log[1]
    postfix = log[2]
    log = log[0]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('localhost', port))
    sock.listen(32)
    credentials = {}
    owner = auth[:12]
    recognition = recognition.replace('\n', ' ')
    timeout = 0 if auth is None or not expiry else (time.time() + expiry)
    try:
        while True:
            try:
                conn = None
                reply = None
                conn, addr = sock.accept()
                msg = split(sock_readline(conn))
                log(prefix + "FROM %r: %s (%d) %s" % (addr, msg[0], len(msg), censor(msg[1:])) + postfix)
                if msg is None:
                    continue
                auth = None
                if (len(msg) == 2 and msg[0] in ('auth', 'kill', 'set', 'list')) \
                    or (len(msg) == 3 and msg[0] == 'get'):
                    auth = msg.pop()
                    ver = verify(auth)
                    if ver:
                        raise Authorize(ver)
                    if expiry:
                        timeout = time.time() + expiry
                    log(prefix + "AUTH %s -> %.1f%s" % (msg[0], timeout, postfix))
                if not auth:
                    if msg[0] in ('auth', 'kill'):
                        raise Fail('Auth required')
                    if msg[0] != 'ping' and time.time() > timeout:
                        raise Authorize('Auth expired')

                if msg[0] == 'ping':
                    reply = "OK\nPong (PID %d)" % getpid()
                elif msg[0] == 'list':
                    reply = 'OK\n' + '\n'.join(credentials.keys())
                elif msg[0] == 'auth':
                    reply = 'OK\nAuthorized'
                elif msg[0] == 'kill':
                    raise Shutdown()
                elif msg[0] == 'get':
                    key = msg[1]
                    if key not in credentials:
                        raise Fail('Key unknown')
                    reply = 'OK\n%s\n%s' % credentials[key]
                elif msg[0] == 'set':
                    reco_out = '%s (PID %d)' % (recognition, getpid())
                    log(prefix + "SECRET" + postfix)
                    conn.sendall('SECRET\n%s\n' % (reco_out, ))
                    _, key, user, pw, reco_in = split(sock_readline(conn))
                    if reco_in != reco_out:
                        raise Fail('Invalid recognition')
                    credentials[key] = (user, pw)
                    reply = 'OK\nCredentials %s/%s set' % (key, user)

            except TypeError:
                continue

            except Authorize as e:
                reply = 'AUTH\n' + str(e)

            except Fail as e:
                reply = 'ERROR\n' + str(e)

            except socket.error as e:
                log(prefix + "ERROR: %s" % (e,) + postfix)
                reply = 'ERROR\n' + str(e)

            except (IndexError, ValueError) as e:
                log(prefix + "ERROR: %s" % (e, ) + postfix)
                reply = "ERROR\nInvalid input"

            finally:
                if conn:
                    if reply:
                        rep = (reply + '\n\n').split('\n', 2)
                        log(prefix + "REPLY: %s\\n%s\\n%s%s" %(rep[0], rep[1], censor(rep[2]), postfix))
                        conn.sendall(reply)
                    conn.close()

    except KeyboardInterrupt:
        log(prefix + "INFO: Interrupted by user." + postfix)

    except Shutdown:
        log(prefix + "INFO: Shutdown requested." + postfix)

    finally:
        try:
            sock.shutdown(1)
        except socket.error:
            # Socket not connected
            pass
        sock.close()
        # Wait for socket to close
        time.sleep(0.25)
