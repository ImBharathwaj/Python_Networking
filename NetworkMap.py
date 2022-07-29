
"""
Part of the program for network mapping
1. The Main program that:
    a. Sets up the network interface in promiscuous mode
    b. Opens a raw socket
    c. Listens and reads packets from the raw socket
    d. Calls the PacketExtractor() function to decode the packet
    e. Updates a list with packets that meet our port criteria
    f. Once the maximum number of packets are collected a unique list is
    generated
2. The PacketExtractor() function that:
    a. Extracts the IP Header
    b. Extracts the TCP Header
    c. Obtains the Source and Destination IP Addresses
    d. Obtains the Source and Destinations Port Numbers
    e. Makes an educated guess as to the Server vs. Client
    f. Returns a list containing ServerIP, ClientIP, ServerPort
"""
import socket           # network interface library used for raw socket
import os               # Operating system function like File I/O
import sys              # system level function like exit()
from struct import *    # Handle strings as binary data

# Constant

PROTOCOL_TCP = 6        # TCP Protocol for IP layer

# PacketExtractor
#
# Purpose: Extracts fields from the IP and TCP Header
# Input:    packet:     buffer from socket.recfrom() method
# Output:   list:       serverIP, clientIP, serverPort
#
def PacketExtractor(packet):
    #Strip off the first 20 character for the ip header
    stripPacket = packet[0:20]

    #now unpack them
    ipHeaderTuple = unpack('!BBHHHBBH4s4s',stripPacket)

    # unpack returns a tuple, for illustration I will extract
    # each individual values

    verLen          = ipHeaderTuple[0]              # Field 0: Version and Lenght 
    TOS             = ipHeaderTuple[1]              # Field 1: Type of service
    packetLength    = ipHeaderTuple[2]              # Field 2: Packet Length
    packetID        = ipHeaderTuple[3]              # Field 3: Identification
    flagFrag        = ipHeaderTuple[4]              # Field 4: Flag/Fragment Offset
    RES             = (flagFrag >> 15) & 0X01       # Reserved
    DF              = (flagFrag >> 14) & 0x01       # Don't Fragment
    MF              = (flagFrag >> 13) & 0x01       # More Fragment
    timeToLive      = ipHeaderTuple[5]              # Field 5: Time To Live (TTL)
    protocol        = ipHeaderTuple[6]              # Field 6: Protocol Number
    checkSum        = ipHeaderTuple[7]              # Field 7: Header Checksum
    sourceIP        = ipHeaderTuple[8]              # Field 8: Source IP
    destIP          = ipHeaderTuple[9]              # Field 9: Destination IP

    # Calculate / Convert extracted values

    version = verLen >> 4       # Upper Nibble is the version number
    length = verLen & 0x0F      # Lower Nibble represents the size
    ipHdrLength = length * 4    # Calculate the header length in bytes
    
    # Convert the source and destination address to dotted notation strings
    sourceAddress = socket.inet_ntoa(sourceIP)
    destinationAddress = socket.inet_ntoa(destIP)

    if protocol == PROTOCOL_TCP:
        
        stripTCPHeader = packet(ipHdrLength:ipHdrLength+20]

        # unpack returns a tuple, for illustration I will extract
        # each individual values using the unpack() function

        tcpHeaderBuffer = unpack('!HHLLBBHH', stripTCPHeader)

        sourcePort          = tcpHeaderBuffer[0]
        destinationPort     = tcpHeaderBuffer[1]
        sequenceNumber      = tcpHeaderBuffer[2]
        acknowledgement     = tcpHeaderBuffer[3]
