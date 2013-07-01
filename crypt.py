#!/usr/bin/env python

import hashlib, base64, sys

hashes = ['md5','sha1','sha256','sha512']
encoding = ['base64','bin','hex','ascii','rot13']
encoded_string = ''
content = ''

def print_usage():
    print ''
    print 'Usage: crypt.py [options] [argument]'
    print ''
    print ' --hash      : hash [md5, sha1, sha256, sha512]'
    print ' --enc       : encoding [base64, rot13]'
    print ' --dec       : encoding [base64, rot13]'
    print ' --string    : string'
    print ' --file      : file'
    print ' --help      : print this help'
    print ''
    print '[argument] = string or file to be hashed'
    print ''
    print 'Example:  crypt.py --hash md5 --string my_password'
    print 'Example:  crypt.py --enc base64 --string secret'
    sys.exit(1)
    
def check_file():
    try:
        f = open(str(sys.argv[4]),  'r')
    except IOError:
        print '[!] The file does not exist or was unable to open.'
        print ''
        sys.exit(1)
    f.close()
    
def import_f():
    f = open(str(sys.argv[4]),'rb')
    content = f.readlines()
    f.close()
    
def md5_hash():
    hash_string = hashlib.md5(clear_string).hexdigest()
    print 'md5 hash:'+ hash_string

def sha1_hash():
    hash_string = hashlib.sha1(clear_string).hexdigest()
    print 'sha1 hash:'+ hash_string

def sha256_hash():
    hash_string = hashlib.sha256(clear_string).hexdigest()
    print 'sha256 hash:'+ hash_string

def sha512_hash():
    hash_string = hashlib.sha512(clear_string).hexdigest()
    print 'sha512 hash:'+ hash_string
    
def base64_encode():
    encoded = base64.b64encode(clear_string)
    print '------- Start of Base64 encoded text below -------'
    print encoded
    print '-------- End of Base64 encoded text above --------'

def base64_decode():
    decoded = base64.decodestring(encoded_string)
    print '------- Decoded text below -------'
    print decoded

def hashing_funcs():
        if str(sys.argv[2]) == 'md5':
            md5_hash()
        if str(sys.argv[2]) == 'sha1':
            sha1_hash()
        if str(sys.argv[2]) == 'sha256':
            sha256_hash()
        if str(sys.argv[2]) == 'sha512':
            sha512_hash()

if len(sys.argv) < 2:                   # If no arguments are sent
    print_usage()
    sys.exit(1)
if str(sys.argv[1]) == '--help':
    print_usage()
    sys.exit(1)
    
if str(sys.argv[1]) == '--hash':            # check if its a hash function
    if str(sys.argv[3]) == '--string':
        clear_string = str(sys.argv[4])
        hashing_funcs()
    if str(sys.argv[3]) == '--file':
        check_file()
        import_f()
        clear_string = content
        hashing_funcs()
      
if str(sys.argv[1]) == '--enc':
    if str(sys.argv[3]) == '--string':
        if str(sys.argv[2]) == 'base64':
            clear_string = str(sys.argv[4])
            base64_encode()
    if str(sys.argv[3]) == '--file':
        check_file()
        import_f()
        clear_string = content
        base64_encode()
        
if str(sys.argv[1]) == '--dec':
    if str(sys.argv[3]) == '--string':
        if str(sys.argv[2]) == 'base64':
            encoded_string = str(sys.argv[4])
            base64_decode()

else:
    sys.exit(1)

## EOF ##
