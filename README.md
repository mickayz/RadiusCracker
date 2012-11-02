RadiusCracker
=============

The radius protocol handles user passwords very insecurely by default.  It relies on a shared secret between the radius server and the user, as well as a unique password for each user.
Often times this shared secret is left default as "testing123".

This tool attempts to guess the shared secret in order to crack the users password, regardless of the password complexity.

To use this tool all you need to do is import a wireshark capture and a shared secret or list of possible shared secrets.  If there are any radius auth packets in the capture, the tool will attempt to crack the password.

NOTE: only use on authorized packet captures :)

[*] USAGE:

python radCrack.py sharedsecret pcapfile

 or 

python radCrack.py -w secretlist pcapfile

ie: 

  python radCrack.py testing123 capture.pcap

  [*] Possible Radius Password Found

  [*] Radius Server: 127.0.0.1

  [*] Username: BobbyBrown          

  [*] Password: ThisISaSuperSecretAndComplexPassword!!@435342534

  [*] Shared Secret: testing123

