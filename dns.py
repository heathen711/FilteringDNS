import time
import SocketServer
import threading
from threading import Thread
import sys
import socket
import fcntl
import struct
import os
import datetime
import string

debug = True

HOST, PORT = "192.168.7.19", 8053

cache = []
cacheMax = 1000

baseDir = "/home/pi/logs/"

historyLog = baseDir + "DNS_history.txt"
errorLog = baseDir + "DNS_error.txt"
debugLog = baseDir + "DNS_debug.txt"

blockFile = "./block.csv"
blockFileTimeStamp = os.stat(blockFile).st_mtime

def history(entry):
    logFile = open(historyLog, "a")
    logFile.write(str(datetime.datetime.now()) + " " + entry + "\n")
    logFile.close()
    
def error_log(entry):
    logFile = open(errorLog, "a")
    logFile.write(str(datetime.datetime.now()) + " " + entry + "\n")
    logFile.close()

def debug_log(entry):
    logFile = open(debugLog, "a")
    logFile.write(str(datetime.datetime.now()) + " " + entry + "\n")
    logFile.close()

class MyUDPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        socket = self.request[1]
        if len(data) > 0:
            client = "New"
            if self.client_address[0].startswith("166."):
                client = "AT&T Network"
            elif self.client_address[0].startswith("76."):
                client = "TWC - 6944"
            elif self.client_address[0].startswith("172."):
                client = "TWC - 9650"
            elif self.client_address[0].startswith("66."):
                client = "Sprint "
            result = DNS(data, self.client_address)
            socket.sendto(result.getPacket(), self.client_address)
            history(client + " " + str(self.client_address[0]) + " -> " + str(result.getDomain()) + " -> " + str(result.getIP()))
        else:
           print "No data..."
        global cache
        if len(cache) > cacheMax:
            for i in range(0, 100):
                cache.pop(0)

def readInBlock():
    if debug:
        debug_log("Reading in block file...")
    global blockFileTimeStamp
    blockFileTimeStamp = os.stat(blockFile).st_mtime
    try:
        block = []
        inFile = file(blockFile, "r")
        data = inFile.readline()
        block = data.split(",\r")
        block.pop(len(block)-1)
        inFile.close()
        return block
    except:
        print "Error reading in block CSV!"
        error_log("Error Reading in block CSV!")
        sys.exit(1)
    
def writeOutBlock(block):
    outFile = file(blockFile, "w")
    for entry in block:
        outFile.write(entry + ",\r")
    outFile.close()

class DNS:
    def askGoogle(self):
        UDP_IP = "8.8.8.8"
        UDP_PORT = 53
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp = sock.sendto(self.data, (UDP_IP, UDP_PORT))
            self.packet, addr = sock.recvfrom(1024)
            self.google = True
            return True
        except:
            self.ip = [ "127.0.0.1" ]
            self.failed = True
            return False
            
    def cacheSearch(self, domain):
        global cache
        if len(cache) < 2:
            return False
        high = len(cache)-1
        low = 0
        mid = high / 2
        done = False
        while low <= high:
            if cache[mid][0] == domain:
                curTime = time.time()
                if curTime <= cache[mid][2]:
                    return cache[mid]
                else:
                    cache.pop(mid)
                    return False
            if domain > cache[mid][0]:
                low = mid + 1
            elif domain < cache[mid][0]:
                high = mid - 1
            mid = (low + high) / 2
        return False
            
    def addToCache(self):
        if self.domain not in doNotCache:
            self.expiration = time.time() + (3*60*60) # add 3 hours in seconds
            cache.append([ self.domain, self.ip, self.expiration ])
            cache.sort()
            
    def notToCache(self):
        for entry in doNotCache:
            if entry in self.domain or self.domain in entry:
                return True
        return False
        
    def redirectSearch(self):
        found = False
        for entry in redirects:
            if self.domain == entry[0]:
                self.ip = [ entry[1] ]
                found = True
        return found
            
    def buildPacket(self):
        self.packet = self.data[0:2] + '\x80\x00' + self.data[4:6] + '\x00' + chr(len(self.ip)) + "\x00\x00\x00\x00" + self.data[12:]
        if not self.failed:
            if self.reverseLookUp:
                tempDomain = self.result.split('.')
                self.packet += '\xc0\x0c\x00\x0C\x00\x01\x00\x00\x00\x3c\x00\x04'
                for sets in tempDomain:
                    self.packet += chr(len(sets)) + sets
                self.packet += '\x00'
                debug_log(self.ID + "Reverse DNS Lookup: " + str(self.ip) + " -> " + str(self.result) + " sent.")
            elif len(self.ip) > 0:
                for ip in self.ip:
                    self.packet += '\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
                    try:
                        self.packet += str.join('',map(lambda x: chr(int(x)), ip.split('.')))
                    except:
                        error_log(self.ID + self.domain + ' -> ' + str(self.ip))
                        self.askGoogle()
                        break
    
    def DNSQuery(self):
        if "\x07version\x04bind" in self.data.lower():
            self.ip = [ ]
        else:
            try:
                tipo = (ord(self.data[2]) >> 3) & 15     # Opcode bits
                if tipo == 0:                                         # Standard query
                    ini = 12
                    lon = ord(self.data[ini])
                    while lon != 0:
                        self.domain += self.data[ini+1 : ini+lon+1] + '.'
                        ini += lon + 1
                        lon = ord(self.data[ini])
                self.domain = self.domain[:-1]
            except:
                error_log(self.ID + "Error processing domain name from " + str(self.data))
                self.askGoogle()
                self.failed = True
            
            if not self.failed:
                if blockFileTimeStamp != os.stat(blockFile).st_mtime:
                    global block
                    block = readInBlock()
                if self.domain.endswith("arpa"):
                    #debug_log(self.ID +  " Arpa:" + self.domain)
                    #lb._dns-sd._udp.0.20.168.192.in-addr.arpa
                    
                    tempIp = self.domain.split('.')
                    for slot in range(len(tempIp)-1, -1, -1):
                        if not tempIp[slot].isdigit():
                            tempIp.pop(slot)
                    if len(tempIp) > 0:        
                        while len(tempIp) < 4:
                            tempIp.insert(0,'0')
                        tempIp = '.'.join([ tempIp[-1], tempIp[-2], tempIp[-3], tempIp[-4] ])
                        debug_log(self.ID + "tempIp: " + str(tempIp))
                        self.ip = [ tempIp ]
                        
                        if self.ip[0] != "0.0.0.0":
                            try:
                                #socket.gethostbyaddr("31.13.77.6")
                                #('edge-star-shv-01-sjc2.facebook.com', ['6.77.13.31.in-addr.arpa'], ['31.13.77.6'])
                                self.result = socket.gethostbyaddr(tempIp)
                            except:
                                error_log(self.ID + "Reverse DNS lookup failed for: " + str(tempIp))
                                debug_log(self.ID + "Reverse DNS lookup failed for: " + str(tempIp) + ' ' + str(sys.exc_info()[0]))
                                self.failed = True

                            if not self.failed:
                                self.result = self.result[0]
                                debug_log(self.ID + str(self.ip) + " -> " + str(self.result))
                                self.reverseLookUp = True
                        else:
                            self.failed = True
                    else:
                        self.ip = []
                #elif "playstation" in self.domain or "sony" in self.domain:
                    #self.ip = socket.gethostbyname("h711.webhop.me")
                elif self.domain == "127.0.0.1":
                    self.ip = [ "127.0.0.1" ]
                elif self.domain == "local":
                    self.ip = [ self.askingIP[0] ]
                elif self.domain == "mg1.pw":
                    command = "echo kekoa711 | sudo -S -p \"\" ipfw add 5000 deny ip from " + self.askingIP[0] + " to me"
                    os.popen(command)
                    self.ip = [ "127.0.0.1" ]
                elif self.domain in block:
                    self.ip = [ "127.0.0.1" ]
                elif self.notToCache():
                    self.askGoogle()
                elif self.redirectSearch():
                    history(self.ID + " Redirected: " + self.domain + " -> " + str(self.ip))
                else:
                    found = self.cacheSearch(self.domain)
                    if found:
                        self.ip = found[1]
                        self.cache = True
                    else:
                        try:
                            name, alias, self.ip = socket.gethostbyname_ex(self.domain)
                            self.addToCache()
                        except:
                            error_log(self.ID + "No IP found for " + self.domain)
                            self.ip = []
                            self.failed = True
                                
        if not self.google:
            self.buildPacket()
    
    def getPacket(self):
        return self.packet
    
    def getIP(self):
        if self.failed:
            return "Unknown"
        elif self.reverseLookUp:
            return self.result
        elif self.google:
            return "Googled"
        elif self.cache:
            return "Cached -> " + str(self.ip)
        elif self.ip == [ "127.0.0.1" ]:
            return "Blocked"
        else:
            return str(self.ip)
        
    def getDomain(self):
        return self.domain
        
    def __init__(self, data, askingIP):
        self.data = data
        self.ID = askingIP[0] + ':' + str(askingIP[1]) + ' '
        self.packet = ''
        self.domain = ''
        self.ip = []
        self.askingIP = askingIP
        self.google = False
        self.failed = False
        self.cache = False
        self.reverseLookUp = False
        
        self.DNSQuery()
        
def udpServer():
    global server
    server = SocketServer.UDPServer((HOST, PORT), MyUDPHandler)
    while 1:
        try:
            server.serve_forever()
        except:
            error_log("Error starting UDP server.")
            time.sleep(1)
    
def udpServerThread():
    udpServerHandler = threading.Thread(target = udpServer)
    udpServerHandler.start()

def cacheSweeper():
    cacheCleanRate = 1 #one second until in sync with clock
    while run:
        now = datetime.datetime.now().time()
        if (now.minute == 0) and (now.second == 0): ##at the top of every hour
            cacheCleanRate = 59*60 ## Set to 59 minutes to save processor cycles
            #debug_log("Cleaning Cache!")
            now = time.time()
            #debug_log("Cache = %d entries." % len(cache))
            for entry in range(len(cache)-1, -1, -1):
                if cache[entry][2] < now:
                    cache.pop(entry)
            #debug_log("Cache = %d entries." % len(cache))
            #debug_log("Done cleaning cache.")
        time.sleep(cacheCleanRate)
        cacheCleanRate = 1
        
def cacheSweeperThread():
    cacheSweeperHandler = threading.Thread(target = cacheSweeper)
    cacheSweeperHandler.start()
    
if __name__ == "__main__":
    global run
    run = True
    global block
    block = readInBlock()
    global doNotCache
    doNotCache = [ "miniclippt.com", "heaven.webhop.me" ]
    global redirects
    redirects = [ ["vvm.mobile.att.net", "166.216.150.131"] ]
    print "Blocked sites loaded."
    udpServerThread()
    global server
    cacheSweeperThread()
    while True:
        try:
            print "Menu:"
            print "1 - add a domain to block"
            print "2 - remove a domain from block"
            print "3 - shutdown"
            choice = raw_input("Choice: ")
            if choice.isdigit():
                choice = int(choice)
                if choice == 1:
                    domain = raw_input("Enter in domain or [Q]uit: ")
                    if domain.lower() != "quit":
                        block.append(domain)
                        block.sort()
                        writeOutBlock(block)
                elif choice == 2:
                    domain = raw_input("Enter in domain or [Q]uit: ")
                    if domain.lower() != "quit":
                        if domain in block:
                            block.pop(block.index(domain))
                        writeOutBlock(block)
                elif choice == 3:
                    server.shutdown()
                    break
                else:
                    print "Invalid option"
            else:
                print "Invalid option"
            print ""
        except KeyboardInterrupt:
            server.shutdown()
            sys.exit(3)
    
    
## Packet Structure
                            
        ## Query ID for this transaction
        #QID = self.data[0:2]
        
        ## Bit-wise indicators
        #bits = ''
        ## 1 bit = Query (0) / Response Flag (1)
        #bits += '1'
        ## 4 bit = Operation Code = a byte = # = 0-5
            ## [ 0:Query, 1:inverse query, 2:status, 3:Not Used, 4:Notify, 5:Update ]
        #bits += '0000'
        ## 1 bit = Authoritative = does this DNS have the last answer for the DNS = 0:no
        #bits += '0'
        ## 1 bit = Truncation flag = was the message over the 512byte size limit for UDP = 0:no
        #bits += '0'
        ## 1 bit = Recursion Desired = asking the server to answer the query recursivly = 0:no
        #bits += '0'
        ## 1 bit = recursion avaliable = 1:supports recursion
        #bits += '0'
        ## 3 bit = Zeros...
        #bits += '000'
        ## 4 bit = response code = a byte = # = 0-10
            ## [ 0: no error, 1: format error, 2: server failure, 3: name error, 4: not implemented
            ##   5: refused, 6: domain should not exist, 7: resource should not exist
            ##   8: missing resource record, 9: not auth for DNS, 10: not auth for Zone ]
        #bits += '0000'
        
        #0x81 = 1000 0001
        #0x80 = 1000 0000
        
        #BitWise = chr(int(bits[0:8],2)) + chr(int(bits[9:], 2))
        #BitWise = '\x80\x00'
        
        ## Total asked and answered
        #QueryCount = self.data[4:6]
        #ResponseCount = '\x00' + chr(len(self.ip))
        #AuthorityCount = "\x00\x00"
        #AddlRecordsCount = "\x00\x00"
        
        ## What was originally asked for
        #OrigQuery = self.data[12:]
        
        ## 0001 0001 0000 01FD 0004 11 8E A0 3B
        
        ## Type of response = [ 1:a host address, 2:an authoritative name server, 12:host ptr, 15:mail exchange ] (Not all but common ones)
        #ResponseQType = '\x00\x01'
        
        ## Query Class, can be anything really
        #QClass = '\x00\x01'
        
        ## TTL (Time To Live)
        #TTL = '\x00\x00\x00\x3c'
        
        #MX_Priority = '\x00\x04'
