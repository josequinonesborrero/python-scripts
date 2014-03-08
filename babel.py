#!/usr/bin/env python

# This script is meant to be used as a single source to process strings and files
# using different types of hashing, encoding and encrypting algorithms.
# Coded by: JQ
# Version: 0.1
# Pending: Add encryption and cracking capabilities, fix file processing

import hashlib, base64, sys

hashes = ['md5','sha1','sha256','sha512']
encoding = ['base64','bin','hex','ascii','rot13']
encoded_string = ''
content = ''

def print_usage():
    print ''
    print 'Usage: babel.py [operation type] [argument] [source type] [argument] [extras]'
    print ''
    print ' --hash      	: hash [md5, sha1, sha256, sha512]'
    print ' --encode    	: encoding [base64, hex, rot13]'
    print ' --decode    	: encoding [base64, hex, rot13]'
    #print ' --crypt	: encryption [aes256]'
    #print ' --decrypt	: encryption [aes256]'
    #print ' --crack	: encryption or hashing [md5, sha1,sha256, sha512, aes256]'
    print ' --string    	: "string"'
    print ' --file      	: file'
    print ' --help      	: print this help'
    print ''
    print '[argument] = string or file to be hashed'
    print ''
    print 'Example:  babel.py --hash md5 --string my_password'
    print 'Example:  babel.py --encode base64 --string secret'
    #print 'Example:  crypt.py --crypt aes256 --string secret --key password'
    sys.exit(1)
    
def import_f():
    try:
        f = open(str(sys.argv[4]),  'rb')
    except IOError:
        print '[!] The file does not exist or was unable to open.'
        print ''
        sys.exit(1)
    content = f.readlines()
    f.close()
    print content
    print '[i] file loaded sucessfully'

def md5_hash():
    hash_string = hashlib.md5(txt_string).hexdigest()
    print 'md5 hash: '+ hash_string

def sha1_hash():
    hash_string = hashlib.sha1(txt_string).hexdigest()
    print 'sha1 hash: '+ hash_string

def sha256_hash():
    hash_string = hashlib.sha256(txt_string).hexdigest()
    print 'sha256 hash: '+ hash_string

def sha512_hash():
    hash_string = hashlib.sha512(txt_string).hexdigest()
    print 'sha512 hash: '+ hash_string
    
def base64_encode():
    encoded = base64.b64encode(txt_string)
    print '------- Start of Base64 encoded text below -------'
    print encoded
    print '-------- End of Base64 encoded text above --------'

def base64_decode():
    decoded = base64.decodestring(encoded_string)
    print '------- Decoded text below -------'
    print decoded
    print '-------- End of Base64 encoded text above --------'
	
def ascii2hex():
    encoded =  txt_string.encode("hex")
    print '------ Start of hex encoded string below ------ '
    print encoded
    print '-------- End of hex encoded text above --------'
	
def hex2ascii():
    decoded = encoded_string.decode("hex")
    print '------ Start of hex decoded string below ------ '
    print decoded
    print '-------- End of hex encoded text above --------'
	
def rot13_encode():
    encoded =  txt_string.encode("rot13")
    print '------ Start of rot13 encoded string below ------ '
    print encoded
    print '-------- End of rot13 encoded text above --------'
	
def rot13_decode():
    decoded = encoded_string.decode("rot13")
    print '------ Start of rot13 decoded string below ------ '
    print decoded
	
def hashing_funcs():					# cycle thru hashing algorithms and hash
        if str(sys.argv[2]) == 'md5':
            md5_hash()
        if str(sys.argv[2]) == 'sha1':
            sha1_hash()
        if str(sys.argv[2]) == 'sha256':
            sha256_hash()
        if str(sys.argv[2]) == 'sha512':
            sha512_hash()

def encoding_funcs():					# cycle thru encoding options and encode
        if str(sys.argv[2]) == 'base64':
            base64_encode()
        if str(sys.argv[2]) == 'hex':
            ascii2hex()
        if str(sys.argv[2]) == 'rot13':
            rot13_encode()

if len(sys.argv) < 2:                                   # If no arguments are sent
    print_usage()
    sys.exit(1)
if str(sys.argv[1]) == '--help':
    print_usage()
    sys.exit(1)
    
if str(sys.argv[1]) == '--hash':                        # check if its a hash function
    if str(sys.argv[3]) == '--string':
        txt_string = str(sys.argv[4])
        hashing_funcs()
    if str(sys.argv[3]) == '--file':
        import_f()
        txt_string = content
        hashing_funcs()
      
if str(sys.argv[1]) == '--encode':			# start of encoding routine
    txt_string = str(sys.argv[4])
    if str(sys.argv[3]) == '--string':
        if str(sys.argv[2]) == 'base64':
            base64_encode()
        if str(sys.argv[2]) == 'hex':
            ascii2hex()
        if str(sys.argv[2]) == 'rot13':
            rot13_encode()

    if str(sys.argv[3]) == '--file':
        content = import_f()
        txt_string = content
        if str(sys.argv[2]) == 'base64':
            base64_decode()
        if str(sys.argv[2]) == 'hex':
            hex2ascii()
        if str(sys.argv[2]) == 'rot13':
            rot13_decode()
			
if str(sys.argv[1]) == '--decode':			# start of decoding strings routine
    encoded_string = str(sys.argv[4])
    if str(sys.argv[3]) == '--string':
        if str(sys.argv[2]) == 'base64':
            base64_decode()
        if str(sys.argv[2]) == 'hex':
            hex2ascii()
        if str(sys.argv[2]) == 'rot13':
            rot13_decode()

else:
    sys.exit(1)

## EOF ##