import os
__doc__ = open(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'README.rst')).read()

def main(argv):
    import docopt
    opts = docopt.docopt(__doc__, argv)
    for opt in ('-p', '-e'):
        if opt in opts:
            opts[opt] = int(opts[opt])

    from . import serve, put, get_yubi_otp
    auth = None
    status = None
    if opts['serve']:
        if not opts['noauth']:
            auth = get_yubi_otp()
        print "Serving on", opts['-p'], "Expiry:", opts['-e']
        serve(auth=auth, port=opts['-p'], expiry=opts['-e'])
    elif opts['auth']:
        auth = get_yubi_otp()
        status, msg = put(opts['-p'], 'yubi', auth)
        if status == 'OK':
            print status, msg
    elif opts['set']:
        if '\n' in opts['<KEY>']:
            sys.exit('Key contains invalid characters')
        if '\n' in opts['<ID>']:
            sys.exit('ID contains invalid characters')
        if '\n' in opts['<VALUE>']:
            sys.exit('Value contains invalid characters')
        if opts.get('-a', None):
            auth = get_yubi_otp()
        status, msg = put(opts['-p'], 'set', opts['<KEY>'], opts['<ID>'], opts['<VALUE>'], auth)
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
