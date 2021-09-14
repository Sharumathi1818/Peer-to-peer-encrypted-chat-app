#! /usr/bin/env python

import socket
import sys
import time
import threading
import pyaes
import hashlib
import pyDH
class Server(threading.Thread):
    def run(self):
        self.sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        print ("Server started successfully\n")
        hostname='192.168.x.x' #enter your ip address
        hostname=socket.gethostname()
        local_ip=socket.gethostbyname(hostname)
        print("hosting on:",local_ip)
        port=51412
        #self.sock.bind((hostname,port))
        self.sock.bind((local_ip,port))
        self.sock.listen(1)
        print ("Listening on port ",port  )      
        #time.sleep(2)    
        (clientname,address)=self.sock.accept()
        print ("Connection from ",  str(address)  )
        def process_bytes(bytess):
            ret = []
            while(len(bytess)>=16):
                if(len(bytess)>=16):
                    byts = bytess[:16]
                    ret.append(byts)
                    bytess = bytess[16:]
                else:
                    print("Block Size Mismatch ")
            return ret
        def process_text(data): 
            streams = []
            while (len(data)>0):
                if(len(data)>=16):
                    stream = data[:16]
                    data = data[16:]
                else:
                    stream = data + ("~"*(16-len(data)))
                    data = ''
                stream_bytes = [ ord(c) for c in stream]
                streams.append(stream_bytes)
            return streams
        
        kk1=clientname.recv(1024) 
        kk1.decode()
        kk1=int(kk1)
        k2 = pyDH.DiffieHellman()
        PubKey2 = str(k2.gen_public_key())

        PubKey2=PubKey2.encode()
        clientname.send(PubKey2)
        SharedKey1 = k2.gen_shared_key(kk1)
        key = str(SharedKey1)
        hashed = hashlib.sha256(key.encode()).digest()
        aes = pyaes.AES(hashed)
        while 1:
            data=clientname.recv(1024)
            if int(data)==1:
                chunk=clientname.recv(4096)
                mess=''
                processed_data = process_bytes(chunk)
                for dat in processed_data:
                    decrypted = aes.decrypt(dat)
                    for ch in decrypted:
                        if(chr(ch)!='~'):
                            mess+=str(chr(ch))
                print("received:>>",mess)
            else:
                filename=input(str("enter the name for the incoming file"))
                file=open(filename,'w')
                file_data=clientname.recv(1024)
                mess=''
                processed_data = process_bytes(file_data)
                for dat in processed_data:
                    decrypted = aes.decrypt(dat)
                    for ch in decrypted:
                        if(chr(ch)!='~'):
                         mess+=str(chr(ch))
                print(mess)
                file.write(mess)
                file.close()
                print("file has been recieved successfullly")
            fi=input("enter 1 for chat,2 for file share")
            f=fi.encode()
            clientname.send(f)
            if int(fi)==1:
                message=input(str(":>>"))
                enc_bytes=[]
                sending_bytes = process_text(message)
                for i in sending_bytes:
                    ciphertext = aes.encrypt(i)
                    enc_bytes+=bytes(ciphertext)
                #print(enc_bytes)
                clientname.send(bytes(enc_bytes))
            elif int(fi)==2:
                enc_bytes=[]
                filename=input(str("plz enter the file name"))
                file=open(filename,'rb')
                file_data=file.read(1024)
     
                file_data=str(file_data)
                sending_bytes = process_text(file_data)
                for i in sending_bytes:
                    ciphertext = aes.encrypt(i)
                    enc_bytes+=bytes(ciphertext)
                clientname.send(bytes(enc_bytes))
                print("data has been transmitted")
                
            

class Client(threading.Thread):    
    def connect(self,host,port):
        self.sock.connect((host,port))
    def run(self):
        self.sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            host=input("Enter the hostname\n>>")            
            port=int(input("Enter the port\n>>"))
        except EOFError:
            print ("Error")
            return 1
        
        print ("Connecting\n")
        s=''
        self.connect(host,port)
        print ("Connected\n")
        k1 = pyDH.DiffieHellman()
        PubKey1 =str( k1.gen_public_key())
        PubKey1=PubKey1.encode()
        self.sock.send (PubKey1)
        kk2=self.sock.recv(1024)
        #print("before decode",kk2)
        kk2.decode()
        #print("after decode",kk2)
        kk2=int(kk2)
        SharedKey2 = k1.gen_shared_key(kk2)
        key = str(SharedKey2)
        def process_bytes(bytess):
            ret = []
            while(len(bytess)>=16):
                if(len(bytess)>=16):
                    byts = bytess[:16]
                    ret.append(byts)
                    bytess = bytess[16:]
                else:
                    print("Block Size Mismatch ")

            return ret
            
                
        def process_text(data): 
            streams = []
            while (len(data)>0):
                if(len(data)>=16):
                    stream = data[:16]
                    data = data[16:]
                else:
                    stream = data + ("~"*(16-len(data)))
                    data = ''
                stream_bytes = [ ord(c) for c in stream]
                streams.append(stream_bytes)
            return streams
            
        while 1:
            
            fi=input(str("enter 1 for chat 2 for file transfer"))
            f=fi.encode()
            self.sock.send(f)
            if int(fi)==1:
                msg=input('>>')
                hashed = hashlib.sha256(key.encode()).digest()
                aes = pyaes.AES(hashed)
                enc_bytes=[]
                sending_bytes = process_text(msg)
                for i in sending_bytes:
                    ciphertext = aes.encrypt(i)
                    enc_bytes+=bytes(ciphertext)
                self.sock.send(bytes(enc_bytes))
            
                
            if int(fi)==2:
                enc_bytes=[]
                filename=input(str("plz enter the file name"))
                file=open(filename,'rb')
                file_data=file.read(1024)
     
                file_data=str(file_data)
                sending_bytes = process_text(file_data)
                for i in sending_bytes:
                    ciphertext = aes.encrypt(i)
                    enc_bytes+=bytes(ciphertext)
                self.sock.send(bytes(enc_bytes))
                print("data has been transmitted")
            data=self.sock.recv(1024)
            if int(data)==1:
                chunk=self.sock.recv(4096)
                mess=''
                processed_data = process_bytes(chunk)
                for dat in processed_data:
                    decrypted = aes.decrypt(dat)
                    for ch in decrypted:
                        if(chr(ch)!='~'):
                            mess+=str(chr(ch))
                print("received:>>",mess)
                
            else:
                filename=input(str("enter the name for the incoming file"))
                file=open(filename,'w')
                file_data=self.sock.recv(1024)
                mess=''
                processed_data = process_bytes(file_data)
                for dat in processed_data:
                    decrypted = aes.decrypt(dat)
                    for ch in decrypted:
                        if(chr(ch)!='~'):
                         mess+=str(chr(ch))
                print(mess)
                file.write(mess)
                file.close()
                print("file has been recieved successfullly")
            

                

                
        return(1)
if __name__=='__main__':
    srv=Server()
    srv.daemon=True
    print ("Starting server")
    srv.start()
    time.sleep(1)
    print ("Starting client")
    cli=Client()
    print ("Started successfully")
    cli.start()
    
    
