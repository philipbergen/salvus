"""
Guide on pypi setup and submit: http://peterdowns.com/posts/first-time-with-pypi.html
"""
__all__ = ['serve']

from .server import serve

def get_yubi_otp():
    from sys import stderr
    from getpass import getpass
    stderr.write("Please touch the yubikey: ")
    stderr.flush()
    res = getpass('')
    if len(res) != 44:
        stderr.write('Some other characters got mixed in. Please try again.\n')
        stderr.flush()
        res = get_yubi_otp()
    return res


def get_socket(port):
    import socket
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect(('localhost', port))
    return conn


def sock_readline(conn, endline='\n'):
    msg = []
    while True:
        ch = conn.recv(1)
        if ch == endline or not ch:
            break
        msg.append(ch)
    return unicode(''.join(msg), 'utf8')


def sock_send(conn, *args):
    pkg = []
    for arg in args:
        if arg is not None:
            pkg.append(unicode(arg).encode('utf8', 'replace').replace('\\', '\\\\').replace(':', '\\:'))
    conn.sendall(':'.join(pkg))
    conn.sendall('\n')
    

def sock_communicate(conn, *args):
    sock_send(conn, *args)
    return sock_readline(conn, '').split('\n')


def sock_close(conn):
    if conn is None:
        return
    from time import sleep
    conn.shutdown(1)
    conn.close()
    sleep(0.25)


def put(port, *args):
    conn = get_socket(port)
    res = sock_communicate(conn, *args)
    sock_close(conn)
    return res

