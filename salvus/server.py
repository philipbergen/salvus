import yubikey
import socket
import time
import sys

def serve(auth=None, yubi_id=17627, port=5999, expiry=3600, log=(sys.stdout.write, 'SALVUS SERVE: ', '\n')):
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
            if res is not None:
                res.append(''.join(tmp))
        return res

    def verify(key, skip_owner=False):
        log(prefix + 'verify ' + str(skip_owner) + ': ' + key + postfix)
        if not yubikey.verify(key, yubi_id):
            return 'Failed validation'
        if not skip_owner and owner != key[:12]:
            return 'Owner mismatch'
        return None

    prefix = log[1]
    postfix = log[2]
    log = log[0]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', port))
    sock.listen(32)
    credentials = {}
    owner = None if auth is None else auth[:12]
    timeout = 0 if auth is None or not expiry else (time.time() + expiry)
    while True:
        try:
            conn = None
            reply = None
            conn, addr = sock.accept()
            msg = []
            while True:
                ch = conn.recv(1)
                if ch == '\n' or not ch:
                    break
                msg.append(ch)
            msg = split(msg)
            log(prefix + "FROM %r: %s" % (addr, msg) + postfix)
            if msg[0] == 'yubi':
                ver = verify(msg[1], owner is None)
                if ver:
                    reply = 'ERROR\n' + ver
                else:
                    if not owner:
                        owner = msg[1][:12]
                        reply = 'OK\nOwner accepted'
                    else:
                        reply = 'OK\nOwner match'
                    if expiry:
                        timeout = time.time() + expiry
            else:
                auth = None
                ver = None
                if not owner:
                    reply = 'AUTH\nNot initialized'
                elif msg[0] == 'get':
                    if len(msg) == 3:
                        auth = msg.pop()
                    key = msg[1]
                    if key not in credentials:
                        reply = 'ERROR\n' + key + ' unknown'
                    else:
                        reply = 'OK\n%s\n%s' % credentials[key]
                elif msg[0] == 'set':
                    if len(msg) == 5:
                        auth = msg.pop()
                        ver = verify(auth)
                    if ver is None:
                        _, key, user, pw = msg
                        credentials[key] = (user, pw)
                        reply = 'OK\n' + key + ' set'
                elif msg[0] == 'list':
                    if len(msg) == 2:
                        auth = msg[-1]
                    reply = 'OK\n' + '\n'.join(credentials.keys())
                else:
                    reply = 'ERROR\nUnknown command: ' + msg
                if auth is not None:
                    if msg[0] != 'set':
                        ver = verify(auth)
                    if ver:
                        reply = 'ERROR\n' + ver

                if auth is None and reply.startswith('OK\n') and time.time() > timeout:
                    reply = 'AUTH\nExpired'
        except socket.error as e:
            log(prefix + "ERROR: %s" % (e,) + postfix)
        
        except (IndexError, ValueError) as e:
            log(prefix + "ERROR: %s" % (e, ) + postfix)
            reply = "ERROR\nInvalid input"

        finally:
            if conn:
                if reply:
                    log(prefix + "REPLY:" + repr(reply) + postfix)
                    conn.sendall(reply)
                conn.close()

