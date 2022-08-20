import os
import platform
import socket
import time
from datetime import datetime

net = input('Enter the network address : ')
net1 = net.split('.')
a = '.'

net2 = net1[0]+a+net1[1]+a+net1[2]+a
st1 = int(input('Enter the starting number : '))
en1 = int(input('Enter the last number : '))
en1 = en1+1
t1 = time.time()

def scan(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = s.connect_ex((addr, 135))
    if result == 0:
        return 1
    else:
        return 0

def run1():
    for ip in range(st1, en1):
        addr = net2 + str(ip)
        if(scan(addr)):
            print(addr, ' is live')

if __name__ == '__main__':
    run1()
    t2 = time.time()
    total = t2-t1
    print('Scanning completed in: %d'% int(total))