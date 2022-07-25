#-*- coding: utf-8 -*-
"""
A demo python code that ..
1) Connects to an IP cam with RTSP
2) Draws RTP/NAL/H264 packets from the camera
3) Writes them to a file that can be read with any stock video player (say, mplayer, vlc & other ffmpeg based video-players)
Done for educative/demonstrative purposes, not for efficiency..!
written 2015 by Sampsa Riikonen.
"""
import socket
import re
import bitstring # if you don't have this from your linux distro, install with "pip install bitstring"
from hashlib import md5
from datetime import datetime
# ************************ FOR QUICK-TESTING EDIT THIS AREA *********************************************************
ip="ip" # IP address of your cam
port="port"
adr="rtsp://"+ip+":"+port+"/onvif1" # username, passwd, etc.
user = "user"
pwd = "pwd"
clientports=[60784,60785] # the client ports we are going to use for receiving video
fname="stream.h265" # filename for dumping the stream
rn=40 # receive this many packets
# After running this program, you can try your file defined in fname with "vlc fname" or "mplayer fname" from the command line
# you might also want to install h264bitstream to analyze your h264 file
# *******************************************************************************************************************
dest="DESCRIBE "+adr+" RTSP/1.0\r\nCSeq: 2\r\nUser-Agent: python\r\nAccept: application/sdp\r\n\r\n"
setu="SETUP "+adr+"/track1 RTSP/1.0\r\nCSeq: 3\r\nUser-Agent: python\r\nTransport: RTP/AVP;unicast;client_port="+str(clientports[0])+"-"+str(clientports[1])+"\r\n\r\n"
play="PLAY "+adr+" RTSP/1.0\r\nCSeq: 5\r\nUser-Agent: python\r\nSession: SESID\r\nRange: npt=0.000-\r\n\r\n"


def gen_key(method,user,pwd,realm,nonce,url):
    ha1 = f"{user}:{realm}:{pwd}"
    HA1 = md5(ha1.encode("UTF-8")).hexdigest()
    ha2 = f"{method}:{url}"
    HA2 = md5(ha2.encode("UTF-8")).hexdigest()
    encrypt_response = f"{HA1}:{nonce}:{HA2}"
    response= md5(encrypt_response.encode("UTF-8")).hexdigest()
    returnkey = 'WWW-Authorization: Digest username="'+user+'", '
    returnkey += 'realm="'+ realm+'", nonce="'+nonce+'", '
    returnkey += 'uri="' + url +'", '
    returnkey += 'response="'+response+'"\r\n'
    return returnkey

def genmsg_SETUP(url,url_add,seq,user,pwd,realm,nonce):
    returnkey = gen_key("SETUP",user,pwd,realm,nonce,url)
    msgRet = "SETUP " + url +url_add+ " RTSP/1.0\r\n"
    msgRet += "CSeq: " + str(seq) + "\r\n"
    msgRet += returnkey
    msgRet += "User-Agent: python\r\n"
    msgRet += "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n"
    msgRet += "\r\n"
    return msgRet

def genmsg_PLAY(url,seq,sessionId,user,pwd,realm,nonce):
    returnkey = gen_key("PLAY",user,pwd,realm,nonce,url)
    msgRet = "PLAY " + url + " RTSP/1.0\r\n"
    msgRet += "CSeq: " + str(seq) + "\r\n"
    msgRet += returnkey
    msgRet += "User-Agent: python\r\n"
    msgRet += "Session: " + sessionId +'\r\n'
    msgRet += "Range: npt=0.000-\r\n"
    msgRet += "\r\n"
    return msgRet

def genmsg_TEARDOWN(url,seq,sessionId,user,pwd,realm,nonce):
    returnkey = gen_key("TEARDOWN",user,pwd,realm,nonce,url)
    msgRet = "TEARDOWN " + url + " RTSP/1.0\r\n"
    msgRet += "CSeq: " + str(seq) + "\r\n"
    msgRet += returnkey
    msgRet += "User-Agent: python\r\n"
    msgRet += "Session: " + sessionId + "\r\n"
    msgRet += "\r\n"
    return msgRet


def find_realm_nonce(msg1):
    # New DESCRIBE with digest authentication
    start = msg1.find("realm")
    begin = msg1.find("\"", start)
    end = msg1.find("\"", begin + 1)
    realm = msg1[begin+1:end]
    
    start = msg1.find("nonce")
    begin = msg1.find("\"", start)
    end = msg1.find("\"", begin + 1)
    nonce = msg1[begin+1:end]
    return realm,nonce

# File organized as follows:
# 1) Strings manipulation routines
# 2) RTP stream handling routine
# 3) Main program
# *** (1) First, some string searching/manipulation for handling the rtsp strings ***
def getPorts(searchst,st):
    """ Searching port numbers from rtsp strings using regular expressions
    """
    pat=re.compile(searchst+"=\d*-\d*")
    pat2=re.compile('\d+')
    mstring=pat.findall(st)[0] # matched string .. "client_port=1000-1001"
    nums=pat2.findall(mstring)
    numas=[]
    for num in nums:
        numas.append(int(num))
    return numas
def getLength(st):
    """ Searching "content-length" from rtsp strings using regular expressions
    """
    pat=re.compile("Content-Length: \d*")
    pat2=re.compile('\d+')
    mstring=pat.findall(st)[0] # matched string.. "Content-Length: 614"
    num=int(pat2.findall(mstring)[0])
    return num
def printrec(recst):
    """ Pretty-printing rtsp strings
    """
    recs=recst.split('\r\n')
    for rec in recs:
        print (rec)
def sessionid(recst):
    """ Search session id from rtsp strings
    """
    recs=recst.split('\r\n')
    for rec in recs:
        ss=rec.split()
        if (ss[0].strip()=="Session:"):
            return str(ss[1].split(";")[0].strip())
def setsesid(recst,idn):
      """ Sets session id in an rtsp string
      """
      return recst.replace("SESID",str(idn))
    
# ********* (2) The routine for handling the RTP stream ***********
def digestpacket(st):
    substr = ''
    #print("start",hex(st[0]),hex(st[1]))
    while st[0] != 0x24 or st[1] != 0x00:
        print(chr(st[0]),end='')
        st = st[1:]
        if len(st)==0:
            print("package Err")    
            return b'',st,1
    msg_len =  int.from_bytes(st[2:4], "big")
    #print("msg_len",msg_len)
    
    if msg_len <= len(st)-4:
        substr = st[msg_len+4:]
        st = st[4:msg_len+4]
        #print('msg len,left len=',len(st),len(substr))
    else:
        #print("continue read...")
        return b'',st,1
    print( ' ------------------------------------')
    """ This routine takes a UDP packet, i.e. a string of bytes and ..
    (a) strips off the RTP header
    (b) adds NAL "stamps" to the packets, so that they are recognized as NAL's
    (c) Concantenates frames
    (d) Returns a packet that can be written to disk as such and that is recognized by stock media players as h264 stream
    """
    #startbytes=[b'\x00',b'\x00',b'\x00',b'\x01'] # this is the sequence of four bytes that identifies a NAL packet.. must be in front of every NAL packet.
    startbytes = bytes([0x00,0x00,0x00,0x01])
    #print((st[0:8]).hex())
    bt=bitstring.BitArray(bytes=st) # turn the whole string-of-bytes packet into a string of bits.  Very unefficient, but hey, this is only for demoing.
    
    #print("head 4 bytes",hex(st[0]), hex(st[1]),hex(st[2]),hex(st[3]))

    version=bt[0:2].uint # version
    p=bt[3] # P
    x=bt[4] # X
    cc=bt[4:8].uint # CC
    m=bt[9] # M
    pt=bt[9:16].uint # PT
    sn=bt[16:32].uint # sequence number
    timestamp=bt[32:64].uint # timestamp
    dt_obj = datetime.fromtimestamp(timestamp)
    #c=bt[64:96].uint # ***c identifier
    # The header format can be found from:
    # https://en.wikipedia.org/wiki/Real-time_Transport_Protocol

    lc=12 # so, we have red twelve bytes
    bc=12*8 # .. and that many bits

    #print("version, p, x, cc, m, pt =",version,p,x,cc,m,pt)
    
    #print("sync. source identifier",c)

    # st=f.read(4*cc) # csrc identifiers, 32 bits (4 bytes) each
    #print('cc',cc)
    cids=[]
    for i in range(cc):
        cids.append(bt[bc:bc+32].uint)
        bc+=32; lc+=4;
    #print("csrc identifiers:",cids)

    if (x):
        # this section haven't been tested.. might fail
        hid=bt[bc:bc+16].uint
        bc+=16; lc+=2;

        hlen=bt[bc:bc+16].uint
        bc+=16; lc+=2;

        #print "ext. header id, header len",hid,hlen
        hst=bt[bc:bc+32*hlen]
        bc+=32*hlen; lc+=4*hlen;
    
    #fb=bt[bc] # i.e. "F"
    #nri=bt[bc+1:bc+3].uint # "NRI"
    #nlu0=bt[bc:bc+3] # "3 NAL UNIT BITS" (i.e. [F | NRI])
    #typ=bt[bc+3:bc+8].uint # "Type"
    typ=bt[bc+1:bc+7].uint # "Type", New Type
    #print "F, NRI, Type :", fb, nri, typ
    #print "first three bits together :",bt[bc:bc+3]
    print("sequence number =",sn,'   Frame  Type   ',typ)
    #if (typ==7 or typ==8):
    if (typ==32 or typ==33 or typ==34): # 33 means SPS_NUT, 34 menas PPS_NUT
        # this means we have either an SPS or a PPS packet
        # they have the meta-info about resolution, etc.
        # more reading for example here:
        # http://www.cardinalpeak.com/blog/the-h-264-sequence-parameter-set/
        if (typ == 32):
            print (">>>>> VPS_NUT packet", "first byte",hex(st[lc]))
        elif (typ==33):
            print (">>>>> SPS_NUT packet", "first byte",hex(st[lc]))
        else:
            print (">>>>> PPS_NUT packet", "first byte",hex(st[lc]))
        ret_str = startbytes+st[lc:]
        print("segment length:",len(ret_str))
        return ret_str,substr,0
    # .. notice here that we include the NAL starting sequence "startbytes" and the "First byte"
    #print("RTP payload len:",len(st[lc:]))
    
    bc+=16; lc+=2; # H265 the first two byte is the FU identifier by wireshark-analyzing
    # The "Type" here is most likely 28, i.e. "FU-A" FU-A is 49
    
    if typ == 49:
        startF = bt[bc] # start bit
        endF = bt[bc+1] # end bit
        #print("start,end=",start,end)
        if (startF): # OK, this is a first fragment in a movie frame
            print(">>>>> first fragment found")
            #nlu=nlu0+nlu1 # Create "[3 NAL UNIT BITS | 5 NAL UNIT BITS]" this is used in H264
            head=startbytes+bytes([0x26,0x01])
            lc+=1 # We skip the "Second byte"
        elif (endF):
            print(">>>>> end fragment found")
            head=b''
            lc+=1 # We skip the "Second byte"
        else:
            head=b''
            lc+=1 # We skip the "Second byte"
        return head+st[lc:],substr,0
    else:
        lc-=2
        return startbytes+st[lc:],substr,0

def recive_packages(s,f,rn):
    try:
        resid,conti = ''.encode(),0
        for i in range(rn):
            #print("========================",i+1,rn,"============================")
            recst = resid + s.recv(4096)
            if len(recst) == 0:
                break
            conti = 0
            #print ("read",len(recst),"bytes")
            while len(recst) != 0 and conti == 0:
                st,recst,conti=digestpacket(recst)
                resid = ''.encode()
                if conti == 1:
                    resid = recst
                if len(st)!=0:
                    #print ("dumping",len(st),"bytes")
                    f.write(st)
    except Exception as e: 
        print(e)
        


# *********** (3) THE MAIN PROGRAM STARTS HERE ****************
# Create an TCP socket for RTSP communication
# further reading: 
# https://docs.python.org/2.7/howto/sockets.html
print(dest)
print(ip,port)
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.settimeout(5)
s.connect((ip,port))
print("connected")
s.send(dest.encode())
recst=s.recv(4096).decode("utf-8")
printrec(recst)

realm,nonce = find_realm_nonce(recst)
setu = genmsg_SETUP(adr,"/track1",3,user,pwd,realm,nonce)
print(setu)
s.send(setu.encode())
recst=s.recv(4096).decode("utf-8")
printrec(recst)
idn=sessionid(recst)

print(idn)

#serverports=getPorts("server_port",recst)
#clientports=getPorts("client_port",recst)
#print ("ip,serverports",ip,serverports)
#print(clientports[0])
s1=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

s1.bind(("", clientports[0])) # we open a port that is visible to the whole internet (the empty string "" takes care of that)
s1.settimeout(5) # if the socket is dead for 5 s., its thrown into trash
# further reading:
# https://wiki.python.org/moin/UdpCommunication
# Now our port is open for receiving shitloads of videodata.  Give the camera the PLAY command..
print ("*** SENDING PLAY ***")
#play=setsesid(play,idn)
play = genmsg_PLAY(adr,5,idn,user,pwd,realm,nonce)
print(play)
s.send(play.encode())

#recst=s.recv(4096)
#printrec(recst)
print ("** STRIPPING RTP INFO AND DUMPING INTO FILE **")
f=open(fname,'wb')

recive_packages(s,f,rn)

teardown = genmsg_TEARDOWN(adr,6,idn,user,pwd,realm,nonce)
print(teardown)
s.send(teardown.encode())

recive_packages(s,f,3000)

f.close()
# Before closing the sockets, we should give the "TEARDOWN" command via RTSP, but I am feeling lazy today (after googling, wireshark-analyzing, among other-things).
s.close()
s1.close()

