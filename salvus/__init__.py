
__all__ = ['serve']

from .server import serve

def get_yubi_otp():
    from sys import stderr
    from getpass import getpass
    stderr.write("Please touch the yubikey: ")
    stderr.flush()
    res = getpass('')
    return res

def put(port, *args):
    import socket
    from time import sleep
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('localhost', port))
    pkg = []
    for arg in args:
        if arg is not None:
            pkg.append(unicode(arg).encode('utf8', 'replace').replace('\\', '\\\\').replace(':', '\\:'))
    s.sendall(':'.join(pkg))
    s.sendall('\n')
    buf = []
    while True:
        data = s.recv(1024)
        if not data:
            break
        buf.append(data)
    s.shutdown(1)
    s.close()
    sleep(0.25)
    return unicode(''.join(buf), 'utf8').split('\n')
    
