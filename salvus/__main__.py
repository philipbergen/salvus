import os
__doc__ = open(os.path.join(os.path.dirname(__file__), 'README.rst')).read()

def main(argv):
    import docopt
    opts = docopt.docopt(__doc__.replace('::', ':').replace(':\n\n', ':\n'), argv)
    for opt in ('-p', '-e'):
        if opt in opts:
            opts[opt] = int(opts[opt])

    from daemonize import Daemonize
    from getpass import getpass
    from socket import error
    from . import serve, put, get_yubi_otp, sock_readline, sock_send, sock_close, sock_communicate, get_socket
    auth = None
    status = None
    if opts['serve']:
        recognition = getpass('Please enter server recognition passphrase (NOT YUBIKEY):')
        auth = get_yubi_otp()
        print "Serving on", opts['-p'], "Expiry:", opts['-e']
        def do_serve(port=opts['-p'], expiry=opts['-e'], auth=auth, recognition=recognition):
            serve(port, expiry, auth, recognition)
        if opts['daemon']:
            daemon = Daemonize(app="Salvus", pid="/tmp/salvus.pid", action=do_serve)
            daemon.start()
        else:
            do_serve()
    elif opts['auth']:
        auth = get_yubi_otp()
        status, msg = put(opts['-p'], 'auth', auth)
        if status == 'OK':
            print status, msg
    elif opts['kill']:
        auth = get_yubi_otp()
        status, msg = put(opts['-p'], 'kill', auth)
        if status == 'OK':
            print status, msg
    elif opts['set']:
        if '\n' in opts['<KEY>']:
            sys.exit('Key contains invalid characters')
        if '\n' in opts['<ID>']:
            sys.exit('ID contains invalid characters')
        if opts.get('-a', None):
            auth = get_yubi_otp()
        try:
            sock = None
            sock = get_socket(opts['-p'])
            sock_send(sock, 'set', auth)
            status, msg = sock_readline(sock), sock_readline(sock)
            if status == 'SECRET':
                recognition = msg
                sys.stderr.write('Do you trust %s? [yn] ' % (recognition, ))
                reply = getpass('')
                if reply in ('y', 'Y', 'yes'):
                    secret = getpass('Please enter secret for %s/%s: ' % (opts['<KEY>'], opts['<ID>']))
                    if '\n' in secret:
                        sys.exit('Secret contains invalid characters')
                    status, msg = sock_communicate(sock, 'ignored', opts['<KEY>'], opts['<ID>'], secret, recognition)
                else:
                    sys.exit('Server is compromised, stop everything you are doing and kill the process')
        finally:
            sock_close(sock)
    elif opts['get']:
        if opts.get('-a', None):
            auth = get_yubi_otp()
        res = put(opts['-p'], 'get', opts['<KEY>'], auth)
        if res[0] == 'OK':
            print res[1]
            print res[2]
        else:
            status, msg = res
    elif opts['list']:
        if opts.get('-a', None):
            auth = get_yubi_otp()
        res = put(opts['-p'], 'list', auth)
        if res[0] == 'OK':
            for key in res[1:]:
                if key:
                    print key
        else:
            status, msg = res
    elif opts['ping']:
        try:
            status, msg = put(opts['-p'], 'ping')
        except error as e:
            status = 'ERROR'
            msg = str(e)

    if status == 'ERROR':
        sys.exit(msg)
    if status == 'AUTH':
        main(argv + ['-a'])

if __name__ == '__main__':
    import sys
    main(sys.argv[1:])
