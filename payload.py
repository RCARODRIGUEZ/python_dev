#! usr/bin/env python

'''
Author: Ricardo Castro Rodrguez CE
Date: 1.4.17
Version 0.5

Description:
Analyze the data in a payload

Notes:

Find a way to create a payload.

Find a way to analythe the data in the payload.

Find a way to corectly send the payload, It has a warning at the end.

Performing test with my Xbox:

Xbox Mac Address:
C0:33:5E:F7:3D:48

Mac MAC Address:
28:CF:E9:4F:D6:AB
'''

import scapy.all
import os
import socket
import sniffer
import sys

# Sniffing packet to find a specifc one.
#
#

def sniffer():
	print "Packet Sniffer-----------------------------------------------"
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
		print "Connection established...."
	except socket.error, msg:
		print "Socket could not be created. Error code: " + str(msg[0]) + " Messge"
		sys.exit()

	packet = s.recvfrom(65565)
	print packet[0:20]
	print "------------------------------------------------------------"
	
def fragment_payload(data):
	print "Fragment the data in the payload"

def create_custom_pkt():
	print "Creat the custom packet"
# Ehter	
	e = scapy.all.Ether()
	e.src = "28:CF:E9:4F:D6:AB"
	e.dst = "C0:33:5E:F7:3D:48"
# IP
	ip = scapy.all.IP()
	ip.dst = "10.0.0.50"
	ip.proto = "tcp"
# Packet
	content = scapy.all.Raw()
	content.load = "THIS IS A TEST"
# TCP
	tcp = scapy.all.TCP()
	tcp.flags = 'S'
	tcp.chksum = 1
	tcp.sport = 1024
	tcp.dport = 2869
	tcp.seq = 1000

# Send the packet---------------------------------------------------------	

	pkt = e/ip/content/tcp
	print "Payload Content---------------------------------------------"
	pkt.show()
	print "------------------------------------------------------------"

	try:
		scapy.all.sendp(pkt)
	# Trying a DDoS
	#	while(True):
	#		scapy.all.sendp(pkt)
	except e:

		print "Error sending the packet - error type : {0}".format(e)

# Display----------------------------------------------

def Display():
	version = 0.5
	print "Payload Manager V{0}".format(version)
	print "----------------------------------------------------------------------"


# Create a custom payload using scapy
# 
#----------------------------------------------------------------------

if __name__ == "__main__":

	Display()
	#create_custom_pkt()
	sniffer()
