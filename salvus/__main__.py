import os
__doc__ = open(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'README.rst')).read()

def main(argv):
    import docopt
    opts = docopt.docopt(__doc__.replace('::', ':').replace(':\n\n', ':\n'), argv)
    for opt in ('-p', '-e'):
        if opt in opts:
            opts[opt] = int(opts[opt])

    from daemonize import Daemonize
    from getpass import getpass
    from . import serve, put, get_yubi_otp
    auth = None
    status = None
    if opts['serve']:
        if not opts['noauth']:
            auth = get_yubi_otp()
        print "Serving on", opts['-p'], "Expiry:", opts['-e']
        def do_serve(auth=auth, port=opts['-p'], expiry=opts['-e']):
            serve(auth=auth, port=port, expiry=expiry)
        if opts['daemon']:
            daemon = Daemonize(app="Salvus", pid="/tmp/salvus.pid", action=do_serve)
            daemon.start()
        else:
            do_serve()
    elif opts['auth']:
        auth = get_yubi_otp()
        status, msg = put(opts['-p'], 'yubi', auth)
        if status == 'OK':
            print status, msg
    elif opts['kill']:
        auth = get_yubi_otp()
        status, msg = put(opts['-p'], 'kill', auth)
    elif opts['set']:
        if '\n' in opts['<KEY>']:
            sys.exit('Key contains invalid characters')
        if '\n' in opts['<ID>']:
            sys.exit('ID contains invalid characters')
        secret = getpass('Please enter secret for %s/%s: ' % (opts['<KEY>'], opts['<ID>']))
        if '\n' in secret:
            sys.exit('Secret contains invalid characters')
        if opts.get('-a', None):
            auth = get_yubi_otp()
        status, msg = put(opts['-p'], 'set', opts['<KEY>'], opts['<ID>'], secret, auth)
    elif opts['get']:
        if opts.get('-a', None):
            auth = get_yubi_otp()
        res = put(opts['-p'], 'get', opts['<KEY>'], auth)
        if res[0] == 'OK':
            print res[1]
            print res[2]
        else:
            status, msg = res

    if status == 'ERROR':
        sys.exit(msg)
    if status == 'AUTH':
        main(argv + ['-a'])

if __name__ == '__main__':
    import sys
    main(sys.argv[1:])
