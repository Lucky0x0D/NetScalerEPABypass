# NetScalerEPABypass
A quick and dirty way to bypass encrypted EPA to connect to a NetScaler Gateway


The Citrix NetScaler Gateway VPN has the ability to check various conditions on a user device when it attempts to connect to a NetScaler 
Gateway. Based on the results of those conditions the NetScaler Gateway decides if a client is permitted to attempt a login, if the client 
is blocked or if the client is to be quarantined. Citrix calls this “Pre-Authentication Endpoint Analysis”, or EPA. This is a problem when 
trying to connect to a NetScaler Gateway VPN without knowing the client-side checks required.

The NetScaler does this by running a client on the user’s machine. On Windows this client is called nsepa.exe. It connects to the 
NetScaler, receives a list of conditions, checks those conditions on the client device and then sends the NetScaler Gateway a result of 
pass or fail.

On the NetScaler this EPA communication can be configured to be in plaintext or be encrypted. When the NetScaler is configured without 
‘Client Security Encryption’ the EPA check is trivial to bypass. 

Previously there was no publicly available way to bypass EPA if ‘Client Security Encryption’ is enabled.

This is a python script that enables encrypted Pre-Authentication Endpoint Analysis to be bypassed almost as trivially as plaintext 
EPA.

Usage:

<PRE>python NSEPA-Bypass.py "NSC_EPAC Cookie Value"  "EPOCH Time from client"  "Value of the HOST: Header" "Base64 encoded string from Server"</PRE>
    
Example Usage :

<PRE>python NSEPA-Bypass.py "981005eef29ce34c80f535f9e78f4b4d" "1498797356"  "vpn.example.com" "WWoNstbK760pVoPwPzHbs9pEf6Tj/iBk55gnHYwptPohBR0bKsiVVZmDN8J8530G4ISIFkRcC/1IaQSiOr8ouOYC84T5Hzbs2yH3Wq/KToo="</PRE>
