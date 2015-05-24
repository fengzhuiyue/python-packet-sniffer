'''
JL Software

Description:
An application that can sniff packets in a local network and displays
	protocol information.

Requirements:
Linux
Windows
Python 2.7

Feature List:
Sniff packets in a local network.
Filter sniffed packets by specific protocol.
Extract specific attributes from a filtered protocol.
Calculate maximum diameter, average diameter, and average packet size

Protocol Support:
Linux:
	Ethernet (MAC)
	ARP
	IP
	ICMP
	TCP
	UDP

Windows:
	IP
	ICMP
	TCP
	UDP
'''

import socket, sys, time, platform
from struct import *

# Global constants for each header length.
constEthHeaderLength = 14
constARPHeaderLength = 28
constIPHeaderLength = 20
constTCPHeaderLength = 20
constUDPHeaderLength = 8
constICMPHeaderLength = 8

# Lists of unpacked packets.
allList = []
arpList = []
icmpList = []
tcpList = []
udpList = []

# Special lists used for calculations and graphs.
lengthList = []
diameterList = []

# Check the OS the application is running on.
os = platform.system()
linux = 'Linux'
windows = 'Windows'

def eth(packet, attKey, printKey):
	# Get Ethernet header using begin and end.
	# No need for windows calibration, Ethernet support under Linux only.
	begin = 0
	end = begin + constEthHeaderLength
	ethHeader = packet[begin:end]

	# Unpack the header because it originally in hex.
	# The regular expression helps unpack the header.
	# ! signifies we are unpacking a network endian.
	# 6s signifies we are unpacking a string of size 6 bytes.
	# H signifies we are unpacking an integer of size 2 bytes.
	ethHeaderUnpacked = unpack('!6s6sH', ethHeader)
		
	# The first 6s is 6 bytes and contains the destination address.
	ethDestAddress = ethHeaderUnpacked[0]
	
	# The second 6s is 6 bytes and contains the source address.
	ethSourceAddress = ethHeaderUnpacked[1]
	
	# The first H is 2 bytes and contains the packet length.
	ethType = socket.ntohs(ethHeaderUnpacked[2])
	
	# Properly unpack and format the destination address.
	ethDestAddress = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % (ord(ethDestAddress[0]), ord(ethDestAddress[1]), ord(ethDestAddress[2]), ord(ethDestAddress[3]), ord(ethDestAddress[4]), ord(ethDestAddress[5]))
	
	# Properly unpack and format the source address.
	ethSourceAddress = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % (ord(ethSourceAddress[0]), ord(ethSourceAddress[1]), ord(ethSourceAddress[2]), ord(ethSourceAddress[3]), ord(ethSourceAddress[4]), ord(ethSourceAddress[5]))
	
	# If the printKey is 0, header information will be printed.
	# 	If the attKey is *, all attributes will be printed.
	# 	If the attKey is not *, the attribute the attKey corresponds to will be printed.
	# If the printKey is not 0, then do not print out the header information.
	# 	If the attKey is not *, the attribute the attKey corresponds to will be returned.
	if printKey == 0:
		# Print Ethernet Header
		print('\n********************\n** Ethernet (MAC) **\n********************')
		
		if (attKey == 0) or (attKey == '*'):
				print('Destination Address: ' + str(ethDestAddress))
		if (attKey == 1) or (attKey == '*'):
				print('Source Address: ' + str(ethSourceAddress))
		if (attKey == 2) or (attKey == '*'):
				print('EtherType: ' + str(ethType))
	else:
		if (attKey == 0):
			return str(ethDestAddress)
		if (attKey == 1):
			return str(ethSourceAddress)
		if (attKey == 2):
			return str(ethType)
	
def arp(packet, attKey, printKey):
	# Get ARP header using begin and end.
	begin = constEthHeaderLength
	end = begin + constARPHeaderLength
	arpHeader = packet[begin:end]
	
	# Unpack the header because it originally in hex.
	# The regular expression helps unpack the header.
	# ! signifies we are unpacking a network endian.
	# H signifies we are unpacking an integer of size 2 bytes.
	# B signifies we are unpacking an integer of size 1 byte.
	# 6s signifies we are unpacking a string of size 6 bytes.
	# 4s signifies we are unpacking a string of size 4 bytes.
	arpHeaderUnpacked = unpack('!HHBBH6s4s6s4s', arpHeader)
	
	# The first H is 2 bytes and contains the hardware type.
	arpHardwareType = socket.ntohs(arpHeaderUnpacked[0])
	
	# The second H is 2 bytes and contains the protocol type.
	arpProtocolType = socket.ntohs(arpHeaderUnpacked[1])
	
	# The first B is 1 byte and contains the hardware address length.
	arpHardAddressLength = arpHeaderUnpacked[2]
	
	# The second B is 1 byte and contains the protocol address length.
	arpProtAddressLength = arpHeaderUnpacked[3]
	
	# The third H is 2 bytes and contains the operation.
	arpOperation = arpHeaderUnpacked[4]

	# The first 6s is 6 bytes and contains the sender hardware address.
	arpSenderHardAddress = arpHeaderUnpacked[5]
	
	# The first 4s is 4 bytes and contains the sender protocol address.
	arpSenderProtAddress = socket.inet_ntoa(arpHeaderUnpacked[6])
	
	# The second 6s is 6 bytes and contains the target hardware address.
	arpTargetHardAddress = arpHeaderUnpacked[7]
	
	# The second 4s is 4 bytes and contains the target protocol address.
	arpTargetProtAddress = socket.inet_ntoa(arpHeaderUnpacked[8])
	
	# Properly unpack and format the source MAC address.
	arpSenderHardAddress = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % (ord(arpSenderHardAddress[0]), ord(arpSenderHardAddress[1]), ord(arpSenderHardAddress[2]), ord(arpSenderHardAddress[3]), ord(arpSenderHardAddress[4]), ord(arpSenderHardAddress[5]))
	
	# Properly unpack and format the destination MAC address.
	arpTargetHardAddress = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x' % (ord(arpTargetHardAddress[0]), ord(arpTargetHardAddress[1]), ord(arpTargetHardAddress[2]), ord(arpTargetHardAddress[3]), ord(arpTargetHardAddress[4]), ord(arpTargetHardAddress[5]))
	
	# If the printKey is 0, header information will be printed.
	# 	If the attKey is *, all attributes will be printed.
	# 	If the attKey is not *, the attribute the attKey corresponds to will be printed.
	# If the printKey is not 0, then do not print out the header information.
	# 	If the attKey is not *, the attribute the attKey corresponds to will be returned.
	if printKey == 0:
		# Print ARP Header
		print('\n*******************\n******* ARP *******\n*******************')
		
		if (attKey == 0) or (attKey == '*'):
			print('Hardware Type: ' + str(arpHardwareType))
		if (attKey == 1) or (attKey == '*'):	
			print('Protocol Type: ' + str(arpProtocolType))
		if (attKey == 2) or (attKey == '*'):	
			print('Hardware Address Length: ' + str(arpHardAddressLength))
		if (attKey == 3) or (attKey == '*'):	
			print('Protocol Address Length: ' + str(arpProtAddressLength))
		if (attKey == 4) or (attKey == '*'):	
			print('Operation: ' + str(arpOperation))
		if (attKey == 5) or (attKey == '*'):	
			print('Sender Hardware Address: ' + str(arpSenderHardAddress))
		if (attKey == 6) or (attKey == '*'):	
			print('Sender Protocol Address: ' + str(arpSenderProtAddress))
		if (attKey == 7) or (attKey == '*'):	
			print('Target Hardware Address: ' + str(arpTargetHardAddress))
		if (attKey == 8) or (attKey == '*'):	
			print('Target Protocol Address: ' + str(arpTargetProtAddress))
			
		# Separator	
		print('\n----------------------------------------')	
	else:
		if (attKey == 0):
			return str(arpHardwareType)
		if (attKey == 1):	
			return str(arpProtocolType)
		if (attKey == 2):	
			return str(arpHardAddressLength)
		if (attKey == 3):	
			return str(arpProtAddressLength)
		if (attKey == 4):	
			return str(arpOperation)
		if (attKey == 5):	
			return str(arpSenderHardAddress)
		if (attKey == 6):	
			return str(arpSenderProtAddress)
		if (attKey == 7):	
			return str(arpTargetHardAddress)
		if (attKey == 8):	
			return str(arpTargetProtAddress)

def ip(packet, attKey, printKey):
	# Get IP header using begin and end.
	# Specific Linux and Windows calibration is needed.
	if os == linux:	
		begin = constEthHeaderLength
		end = begin + constIPHeaderLength
	elif os == windows:
		begin = 0
		end = begin + constIPHeaderLength
	ipHeader = packet[begin:end]

	# Unpack the header because it originally in hex.
	# The regular expression helps unpack the header.
	# ! signifies we are unpacking a network endian.
	# B signifies we are unpacking an integer of size 1 byte.
	# H signifies we are unpacking an integer of size 2 bytes.
	# 4s signifies we are unpacking a string of size 4 bytes.
	ipHeaderUnpacked = unpack('!BBHHHBBH4s4s' , ipHeader)
	
	# The first B is 1 byte and contains the version and header length.
	# Both are 4 bits each, split ipHeaderUnpacked[0] in "half".
	ipVersionAndHeaderLength = ipHeaderUnpacked[0]
	ipVersion = ipVersionAndHeaderLength >> 4
	ipHeaderLength = ipVersionAndHeaderLength & 0xF

	# The second B is 1 byte and contains the service type and ECN.
	ipDSCPAndECN = ipHeaderUnpacked[1]
	ipDSCP = ipDSCPAndECN >> 2
	ipECN = ipDSCPAndECN & 0x3

	# The first H is 2 bytes and contains the total length.
	ipTotalLength = ipHeaderUnpacked[2]
	
	# The second H is 2 bytes and contains the total length.
	ipIdentification = ipHeaderUnpacked[3]

	# The third H is 2 bytes and contains the flags and fragment offset.
	# Flags is 3 bits and fragment offset is 13 bits.
	# Split ipHeaderUnpacked[4].
	ipFlagsAndFragmentOffset = ipHeaderUnpacked[4]
	ipFlags = ipFlagsAndFragmentOffset >> 13
	ipFragmentOffset = ipFlagsAndFragmentOffset & 0x1FFF

	# The third B is 1 byte and contains the time to live.
	ipTimeToLive = ipHeaderUnpacked[5]
		
	# Our fourth B is 1 byte and contains the protocol.
	ipProtocol = ipHeaderUnpacked[6]
	
	# The fourth H is 2 bytes and contains the header checksum.
	ipHeaderChecksum = ipHeaderUnpacked[7]

	# The first 4s is 4 bytes and contains the source address.
	ipSourceAddress = socket.inet_ntoa(ipHeaderUnpacked[8]);

	# The second 4s is 4 bytes and contains the dest address.
	ipDestAddress = socket.inet_ntoa(ipHeaderUnpacked[9]);

	# If the printKey is 0, header information will be printed.
	# 	If the attKey is *, all attributes will be printed.
	# 	If the attKey is not *, the attribute the attKey corresponds to will be printed.
	# If the printKey is not 0, then do not print out the header information.
	# 	If the attKey is not *, the attribute the attKey corresponds to will be returned.
	if printKey == 0:
		# Print IP Header
		# Some segments of the header are switched back to hex form because that
		# 	is the format wireshark has it.
		print('\n********************\n******** IP ********\n********************')
		
		if (attKey == 0) or (attKey == '*'):
			print('Version: ' + str(ipVersion))
		if (attKey == 1) or (attKey == '*'):
			print('Header Length: ' + str(ipHeaderLength) + ' 32-bit words')
		if (attKey == 2) or (attKey == '*'):
			print('Differentiated Services Code Point: ' + format(ipDSCP, '#04X') + ' , ' + str(ipDSCP))
		if (attKey == 3) or (attKey == '*'):
			print('Explicit Congestion Notification: ' + format(ipECN, '#04X') + ' , ' + str(ipECN))
		if (attKey == 4) or (attKey == '*'):
			print('Total Length: ' + str(ipTotalLength) + ' bytes')
		if (attKey == 5) or (attKey == '*'):
			print('Identification: ' + format(ipIdentification, '#04X') + ' , ' + str(ipIdentification))
		if (attKey == 6) or (attKey == '*'):
			print('Flags: ' + format(ipFlags, '#04X') + ' , ' + str(ipFlags))
		if (attKey == 7) or (attKey == '*'):
			print('Fragment Offset: ' + str(ipFragmentOffset) + ' eight-byte blocks')
		if (attKey == 8) or (attKey == '*'):
			print('Time to Live: ' + str(ipTimeToLive) + ' hops')
		if (attKey == 9) or (attKey == '*'):
			print('Protocol: ' + str(ipProtocol))
		if (attKey == 10) or (attKey == '*'):
			print('Header Checksum: ' + format(ipHeaderChecksum, '#04X'))
		if (attKey == 11) or (attKey == '*'):
			print('Source Address: ' + str(ipSourceAddress))
		if (attKey == 12) or (attKey == '*'):
			print('Destination Address: ' + str(ipDestAddress))
	else:
		if (attKey == 0):
			return str(ipVersion)
		if (attKey == 1):
			return str(ipHeaderLength)
		if (attKey == 2):
			return format(ipDSCP, '#04X')
		if (attKey == 3):
			return format(ipECN, '#04X')
		if (attKey == 4):
			return str(ipTotalLength)
		if (attKey == 5):
			return format(ipIdentification, '#04X')
		if (attKey == 6):
			return format(ipFlags, '#04X')
		if (attKey == 7):
			return str(ipFragmentOffset)
		if (attKey == 8):
			return str(ipTimeToLive)
		if (attKey == 9):
			return str(ipProtocol)
		if (attKey == 10):
			return format(ipHeaderChecksum, '#04X')
		if (attKey == 11):
			return str(ipSourceAddress)
		if (attKey == 12):
			return str(ipDestAddress)
			
def icmp(packet, attKey, printKey):
	# Get ICMP header using begin and end.
	# Specific Linux and Windows calibration is needed.
	if os == linux:
		begin = constEthHeaderLength + constIPHeaderLength
		end = begin + constICMPHeaderLength
	elif os == windows:
		begin = constIPHeaderLength
		end = begin + constICMPHeaderLength
	icmpHeader = packet[begin:end]

	# Unpack the header because it originally in hex.
	# The regular expression helps unpack the header.
	# ! signifies we are unpacking a network endian.
	# B signifies we are unpacking an integer of size 1 byte.
	# H signifies we are unpacking an integer of size 2 bytes.
	# L signifies we are unpacking a long of size 4 bytes.
	icmpHeaderUnpacked = unpack('!BBHL', icmpHeader)

	# The first B is 1 byte and contains the type.
	icmpType = icmpHeaderUnpacked[0]

	# The second B is 1 byte and contains the code.
	icmpCode = icmpHeaderUnpacked[1]

	# The first H is 2 bytes and contains the checksum.
	icmpChecksum = icmpHeaderUnpacked[2]

	# Check if the type is 1 or 8, if so, unpack the identifier and sequence number.
	if (icmpType == 0) or (icmpType == 8):
		# The first L is 4 bytes and contains the rest of the header.
		icmpIdentifier = icmpHeaderUnpacked[3] >> 16
		icmpSeqNumber = icmpHeaderUnpacked[3] & 0xFFFF

	# If the printKey is 0, header information will be printed.
	# 	If the attKey is *, all attributes will be printed.
	# 	If the attKey is not *, the attribute the attKey corresponds to will be printed.
	# If the printKey is not 0, then do not print out the header information.
	# 	If the attKey is not *, the attribute the attKey corresponds to will be returned.
	if printKey == 0:
		if (icmpType == 0) or (icmpType == 8):
			# Print ICMP Header
			# Some segments of the header are switched back to hex form because that
			# 	is the format wireshark has it.
			print('\n********************\n******* ICMP *******\n********************')
			
			if (attKey == 0) or (attKey == '*'):
				print('Type: ' + str(icmpType))
			if (attKey == 1) or (attKey == '*'):
				print('Code: ' + str(icmpCode))
			if (attKey == 2) or (attKey == '*'):
				print('Checksum: ' + format(icmpChecksum, '#04X'))
			if (attKey == 3) or (attKey == '*'):
				print('Identifier: ' + str(icmpIdentifier))
			if (attKey == 4) or (attKey == '*'):
				print('Sequence Number: ' + str(icmpSeqNumber))
		else:
			print('\n********************\n******* ICMP *******\n********************')
			
			if (attKey == 0) or (attKey == '*'):
				print('Type: ' + str(icmpType))
			if (attKey == 1) or (attKey == '*'):
				print('Code: ' + str(icmpCode))
			if (attKey == 2) or (attKey == '*'):
				print('Checksum: ' + format(icmpChecksum, '#04X'))
			if (attKey == 3) or (attKey == '*'):
				print('Attribute not available.')
			if (attKey == 4) or (attKey == '*'):
				print('Attribute not available.')
				
		# Separator	
		print('\n----------------------------------------')
	else:
		if (icmpType == 0) or (icmpType == 8):
			if (attKey == 0):
				return str(icmpType)
			if (attKey == 1):
				return str(icmpCode)
			if (attKey == 2):
				return format(icmpChecksum, '#04X')
			if (attKey == 3):
				return str(icmpIdentifier)
			if (attKey == 4):
				return str(icmpSeqNumber)
		else:			
			if (attKey == 0):
				return str(icmpType)
			if (attKey == 1):
				return str(icmpCode)
			if (attKey == 2):
				return format(icmpChecksum, '#04X')
			if (attKey == 3):
				return 'Attribute not available.'
			if (attKey == 4):
				return 'Attribute not available.'
	
def tcp(packet, attKey, printKey):
	# Get TCP header using begin and end.
	# Specific Linux and Windows calibration is needed.
	if os == linux:
		begin = constEthHeaderLength + constIPHeaderLength
		end = begin + constTCPHeaderLength
	elif os == windows:
		begin = constIPHeaderLength
		end = begin + constTCPHeaderLength
	tcpHeader = packet[begin:end]

	# Unpack the header because it originally in hex.
	# The regular expression helps unpack the header.
	# ! signifies we are unpacking a network endian.
	# H signifies we are unpacking an integer of size 2 bytes.
	# L signifies we are unpacking a long of size 4 bytes.
	# B signifies we are unpacking an integer of size 1 byte.
	tcpHeaderUnpacked = unpack('!HHLLBBHHH', tcpHeader)
	
	# The first H is 2 bytes and contains the source port.
	tcpSourcePort = tcpHeaderUnpacked[0]
	
	# The second H is 2 bytes and contains the destination port.
	tcpDestPort = tcpHeaderUnpacked[1]

	# The first L is 2 bytes and contains the sequence number.
	tcpSeqNumber = tcpHeaderUnpacked[2]
	
	# The second L is 4 bytes and contains the acknowledgement number.
	tcpAckNumber = tcpHeaderUnpacked[3]
	
	# The first B is 1 byte and contains the data offset, reserved bits, and NS flag.
	# Split tcpHeaderUnpacked[4]
	tcpDataOffsetAndReserved = tcpHeaderUnpacked[4]
	tcpDataOffset = tcpDataOffsetAndReserved >> 4
	tcpReserved = (tcpDataOffsetAndReserved >> 1) & 0x7
	tcpNSFlag = tcpDataOffsetAndReserved & 0x1
	
	# The second B is 1 byte and contains the rest of the flags.
	# Split tcpHeaderUnpacked[5].
	tcpRestOfFLags = tcpHeaderUnpacked[5]
	tcpCWRFlag = tcpRestOfFLags >> 7
	tcpECEFlag = (tcpRestOfFLags >> 6) & 0x1
	tcpURGFlag = (tcpRestOfFLags >> 5) & 0x1
	tcpACKFlag = (tcpRestOfFLags >> 4) & 0x1
	tcpPSHFlag = (tcpRestOfFLags >> 3) & 0x1
	tcpRSTFlag = (tcpRestOfFLags >> 2) & 0x1
	tcpSYNFlag = (tcpRestOfFLags >> 1) & 0x1
	tcpFINFlag = tcpRestOfFLags & 0x1
	
	# The third H is 2 bytes and contains the window size.
	tcpWindowSize = tcpHeaderUnpacked[6]
	
	# The fourth H is 2 byte and conntains the checksum.
	tcpChecksum = tcpHeaderUnpacked[7]
	
	# The fifth H is 2 bytes and constains the urgent pointer.
	tcpUrgentPointer = tcpHeaderUnpacked[8]

	# If the printKey is 0, header information will be printed.
	# 	If the attKey is *, all attributes will be printed.
	# 	If the attKey is not *, the attribute the attKey corresponds to will be printed.
	# If the printKey is not 0, then do not print out the header information.
	# 	If the attKey is not *, the attribute the attKey corresponds to will be returned.
	if printKey == 0:
		# Print TCP Header
		# Some segments of the header are switched back to hex form because that
		# 	is the format wireshark has it.
		print('\n*******************\n******* TCP *******\n*******************')
	
		if (attKey == 0) or (attKey == '*'):
			print('Source Port: ' + str(tcpSourcePort))
		if (attKey == 1) or (attKey == '*'):
			print('Destination Port: ' + str(tcpDestPort))
		if (attKey == 2) or (attKey == '*'):
			print('Sequence Number: ' + str(tcpSeqNumber))
		if (attKey == 3) or (attKey == '*'):
			print('Acknowledgment Number: ' + str(tcpAckNumber))
		if (attKey == 4) or (attKey == '*'):
			print('Data Offset: ' + str(tcpDataOffset) + ' 32-bit words')
		if (attKey == 5) or (attKey == '*'):
			print('Reserved: ' + format(tcpReserved, '03b') + '. .... ....')
		if (attKey == 6) or (attKey == '*'):
			print('NS Flag:  ' + '...' + format(tcpNSFlag, '01b') + ' .... ....')
		if (attKey == 7) or (attKey == '*'):
			print('CWR Flag: ' + '.... ' + format(tcpCWRFlag, '01b') + '... ....')
		if (attKey == 8) or (attKey == '*'):
			print('ECE Flag: ' + '.... .' + format(tcpECEFlag, '01b') + '.. ....')
		if (attKey == 9) or (attKey == '*'):
			print('URG Flag: ' + '.... ..' + format(tcpURGFlag, '01b') + '. ....')
		if (attKey == 10) or (attKey == '*'):
			print('ACK Flag: ' + '.... ...' + format(tcpACKFlag, '01b') + ' ....')
		if (attKey == 11) or (attKey == '*'):
			print('PSH Flag: ' + '.... .... ' + format(tcpPSHFlag, '01b') + '...')
		if (attKey == 12) or (attKey == '*'):
			print('RST Flag: ' + '.... .... .' + format(tcpRSTFlag, '01b') + '..')
		if (attKey == 13) or (attKey == '*'):
			print('SYN Flag: ' + '.... .... ..' + format(tcpSYNFlag, '01b') + '.')
		if (attKey == 14) or (attKey == '*'):
			print('FIN Flag: ' + '.... .... ...' + format(tcpFINFlag, '01b'))
		if (attKey == 15) or (attKey == '*'):
			print('Window Size: ' + str(tcpWindowSize) + ' bytes')
		if (attKey == 16) or (attKey == '*'):
			print('Urgent Pointer: ' + str(tcpUrgentPointer))
		if (attKey == 17) or (attKey == '*'):
			print('Checksum: ' + format(tcpChecksum, '#04X'))
	
		# Separator	
		print('\n----------------------------------------')	
	else:
		if (attKey == 0):
			return str(tcpSourcePort)
		if (attKey == 1):
			return str(tcpDestPort)
		if (attKey == 2):
			return str(tcpSeqNumber)
		if (attKey == 3):
			return str(tcpAckNumber)
		if (attKey == 4):
			return str(tcpDataOffset)
		if (attKey == 5):
			return format(tcpReserved, '03b')
		if (attKey == 6):
			return format(tcpNSFlag, '01b')
		if (attKey == 7):
			return format(tcpCWRFlag, '01b')
		if (attKey == 8):
			return format(tcpECEFlag, '01b')
		if (attKey == 9):
			return format(tcpURGFlag, '01b')
		if (attKey == 10):
			return format(tcpACKFlag, '01b')
		if (attKey == 11):
			return format(tcpPSHFlag, '01b')
		if (attKey == 12):
			return format(tcpRSTFlag, '01b')
		if (attKey == 13):
			return format(tcpSYNFlag, '01b')
		if (attKey == 14):
			return format(tcpFINFlag, '01b')
		if (attKey == 15):
			return str(tcpWindowSize)
		if (attKey == 16):
			return str(tcpUrgentPointer)
		if (attKey == 17):
			return format(tcpChecksum, '#04X')

def udp(packet, attKey, printKey):
	# Get UDP header using begin and end.
	# Specific Linux and Windows calibration is needed.
	if os == linux:
		begin = constEthHeaderLength + constIPHeaderLength
		end = begin + constUDPHeaderLength
	elif os == windows:
		begin = constIPHeaderLength
		end = begin + constUDPHeaderLength
	udpHeader = packet[begin:end]

	# Unpack the header because it originally in hex.
	# The regular expression helps unpack the header.
	# ! signifies we are unpacking a network endian.
	# H signifies we are unpacking an integer of size 2 bytes.
	udpHeaderUnpacked = unpack('!HHHH', udpHeader)
	 
	# The first H is 2 bytes and contains the source port.
	udpSourcePort = udpHeaderUnpacked[0]
	
	# The second H is 2 bytes and contains the destination port.
	udpDestPort = udpHeaderUnpacked[1]
	
	# The third H is 2 bytes and contains the packet length.
	udpLength = udpHeaderUnpacked[2]
	
	# The fourth H is 2 bytes and contains the header checksum.
	udpChecksum = udpHeaderUnpacked[3]
	
	# If the printKey is 0, header information will be printed.
	# 	If the attKey is *, all attributes will be printed.
	# 	If the attKey is not *, the attribute the attKey corresponds to will be printed.
	# If the printKey is not 0, then do not print out the header information.
	# 	If the attKey is not *, the attribute the attKey corresponds to will be returned.
	if printKey == 0:
		# Print UDP Header
		print('\n*******************\n******* UDP *******\n*******************')
		
		if (attKey == 0) or (attKey == '*'):
			print('Source Port: ' + str(udpSourcePort))
		if (attKey == 1) or (attKey == '*'):
			print('Destination Port: ' + str(udpDestPort))
		if (attKey == 2) or (attKey == '*'):
			print('Length: ' + str(udpLength) + ' bytes')
		if (attKey == 3) or (attKey == '*'):
			print('Checksum: ' + format(udpChecksum, '#04X'))

		# Separator	
		print('\n----------------------------------------')	
	else:
		if (attKey == 0):
			return str(udpSourcePort)
		if (attKey == 1):
			return str(udpDestPort)
		if (attKey == 2):
			return str(udpLength)
		if (attKey == 3):
			return format(udpChecksum, '#04X')
	
def unpackAndDisplay(packet):
	# All attributes for each protocol will be displayed.
	attKey = '*'
	
	# Attributes will be printed.
	printKey = 0
	
	# If the OS is Linux, unpack Ethernet's protocol.
	# If the OS is Windows, mimic unpacking Ethernet's protocol.
	if os == linux:
		# Unpack the Ethernet (MAC) information.
		eth(packet, attKey, printKey)
	
		# Find the packet's Ethernet protocol.
		ethProtocol = int(eth(packet, 2, 1))
	elif os == windows:
		ethProtocol = 8

	# Find if the Ethernet frame is ARP or IP.
	if ethProtocol == 1544:
		# Unpack the ARP information.
		arp(packet, attKey, printKey)
	elif ethProtocol == 8:
		# Unpack the IP information.
		ip(packet, attKey, printKey)
		
		# Find the packet's IP protocol.
		ipProtocol = int(ip(packet, 9, 1))
			
		# If the protocol is 1, meaning ICMP, then unpack the ICMP information.
		# If the protocol is 6, meaning TCP, then unpack the TCP information.
		# If the protocol is 17, meaning UDP, then unpack the UDP information.
		if ipProtocol == 1:
			icmp(packet, attKey, printKey)
		elif ipProtocol == 6:
			tcp(packet, attKey, printKey)
		elif ipProtocol == 17:
			udp(packet, attKey, printKey)

def unpackAndSave(packet):
	# If the OS is Linux, unpack Ethernet's protocol.
	# If the OS is Windows, mimic unpacking Ethernet's protocol.
	if os == linux:
		# Find the packet's Ethernet protocol.
		ethProtocol = int(eth(packet, 2, 1))
	elif os == windows:
		ethProtocol = 8

	# Find if the Ethernet frame is ARP or IP.
	# If the protocol is 1544, meaning ARP, then unpack and save the ARP information.
	# If the protocol is 8, meaning IP, find the diameter and find the protocol within IP.
	if ethProtocol == 1544:
		allList.append(packet)
		arpList.append(packet)
	elif ethProtocol == 8:
		# Find the packet's IP protocol.
		ipProtocol = int(ip(packet, 9, 1))
		
		# Append the IP total length to the length list.
		# Append the diameters to the diameter list using TTL.
		# These will be used for calculations and graphs.
		ipTotalLength = int(ip(packet, 4, 1))
		lengthList.append(ipTotalLength)
			
		# Find the diameter of the network.
		# Different servers have different operating systems that have different TTLs.
		# Cisco is 255, Windows is 128, Linux is 64.
		ipTimeToLive = int(ip(packet, 8, 1))
		
		if ipTimeToLive > 128:
			diameterList.append(255 - ipTimeToLive)
		elif ipTimeToLive > 64:
			diameterList.append(128 - ipTimeToLive)
		else:
			diameterList.append(64 - ipTimeToLive)
		
		# If the protocol is 1, meaning ICMP, then unpack and save the ICMP information.
		# If the protocol is 6, meaning TCP, then unpack and save the TCP information.
		# If the protocol is 17, meaning UDP, then unpack and save the UDP information.
		if ipProtocol == 1:
			allList.append(packet)
			icmpList.append(packet)
		elif ipProtocol == 6:
			allList.append(packet)
			tcpList.append(packet)
		elif ipProtocol == 17:
			allList.append(packet)
			udpList.append(packet)

def linuxFilter():
	# Repeated if incorrect input.
	while True:
		# Display filtering options.
		filteredProtocol = raw_input('0: ARP\n1: ICMP\n2: TCP\n3: UDP\nCtrl+c to stop...\nSelection: ')
		
		# Check if decision is supported input.
		try:
			filteredProtocol = int(filteredProtocol)
		except ValueError:
			print('\nUnsupported input, try again...')
			continue
		
		# All attributes for each protocol will be displayed.
		attKey = '*'
		
		# Attributes will be printed.
		printKey = 0

		# Filter based on input, if input is not supported, notify user.
		# If no protocols of certain type were filtered, notify user.
		# If user chooses cancel option, break while loop, thus stopping the filtering.
		if filteredProtocol == 0:
			# Find the length of the protocol's list.
			length = len(arpList)
			
			# If the length is not empty, unpack and display the packets in the list.
			# 	Then return the associated number of protocol being filtered.
			# If length is empty, notify user.
			if length > 0:
				for i in range(length):
					packet = arpList[i]
					unpackAndDisplay(packet)
				return filteredProtocol
			else:
				print('\nNo protocols of this type were sniffed.')
		elif filteredProtocol == 1:
			length = len(icmpList)
			
			if length > 0:
				for i in range(length):
					packet = icmpList[i]
					unpackAndDisplay(packet)
				return filteredProtocol
			else:
				print('\nNo protocols of this type were sniffed.')
		elif filteredProtocol == 2:
			length = len(tcpList)
			
			if length > 0:
				for i in range(length):
					packet = tcpList[i]
					unpackAndDisplay(packet)
				return filteredProtocol
			else:
				print('\nNo protocols of this type were sniffed.')
		elif filteredProtocol == 3:
			length = len(udpList)
			
			if length > 0:
				for i in range(length):
					packet = udpList[i]
					unpackAndDisplay(packet)
				return filteredProtocol
			else:
				print('\nNo protocols of this type were sniffed.')
		else:
			print('\nUnsupported input, try again...')
			
def windowsFilter():
	while True:
		# Display filtering options.
		# Repeated if incorrect input.
		filteredProtocol = raw_input('0: ICMP\n1: TCP\n2: UDP\nCtrl+c to stop...\nSelection: ')
		
		# Check if decision is supported input.
		try:
			filteredProtocol = int(filteredProtocol)
		except ValueError:
			print('\nUnsupported input, try again...')
			continue
		
		# All attributes for each protocol will be displayed.
		attKey = '*'
		
		# Attributes will be printed.
		printKey = 0

		# Filter based on input, if input is not supported, notify user.
		# If no protocols of certain type were filtered, notify user.
		# If user chooses cancel option, break while loop.
		if filteredProtocol == 0:
			# Find the length of the protocol's list.
			length = len(icmpList)
			
			# If the length is not empty, unpack the packets in the list.
			# If length is empty, notify user and return the associated number of protocol being filtered.
			if length > 0:
				for i in range(length):
					packet = icmpList[i]
					unpackAndDisplay(packet)
				return filteredProtocol
			else:
				print('\nNo protocols of this type were sniffed.')
		elif filteredProtocol == 1:
			length = len(tcpList)
			
			if length > 0:
				for i in range(length):
					packet = tcpList[i]
					unpackAndDisplay(packet)
				return filteredProtocol
			else:
				print('\nNo protocols of this type were sniffed.')
		elif filteredProtocol == 2:
			length = len(udpList)
			
			if length > 0:
				for i in range(length):
					packet = udpList[i]
					unpackAndDisplay(packet)
				return filteredProtocol
			else:
				print('\nNo protocols of this type were sniffed.')
		else:
			print('\nUnsupported input, try again...')

def linuxExtract(filteredProtocol):
	# Establish the prompts for each protocol's attributes.
	ethAttributes = '0: Destination Address\n1: Source Address\n2: EtherType'
	arpAttributes = '3: Hardware Type\n4: Protocol Type\n5: Hardware Address Length\n6: Protocol Address Length\n7: Operation\n8: Sender Hardware Address\n9: Sender Protocol Address\n10: Target Hardware Address\n11: Target Protocol Address'
	ipAttributes = 	'3: Version\n4: Header Length\n5: Differentiated Services Code Point\n6: Explicit Congestion Notification\n7: Total Length\n8: Identification\n9: Flags\n10: Fragment Offset\n11: Time to Live\n12: Protocol\n13: Header Checksum\n14: Source Address\n15: Destination Address'
	icmpAttributes = '16: Type\n17: Code\n18: Checksum\n19: Identifier (If available)\n20: Sequence Number (If available)'
	tcpAttributes = '16: Source Port\n17: Destination Port\n18: Sequence Number\n19: Acknowledgment Number\n20: Data Offset\n21: Reserved\n22: NS Flag\n23: CWR Flag\n24: ECE Flag\n25: URG Flag\n26: ACK Flag\n27: PSH Flag\n28: RST Flag\n29: SYN Flag\n30: FIN Flag\n31: Window Size\n32: Urgent Pointer\n33: Checksum'
	udpAttributes = '16: Source Port\n17: Destination Port\n18: Length\n19: Checksum'
	
	# Attributes will be printed.
	printKey = 0
	
	# Repeated if incorrect input.
	while True:
		# Find the filtered protocol specified by the user.
		if filteredProtocol == 0:
			# Display the approriate attributes available from the filtered protocol.
			print(ethAttributes)
			print(arpAttributes)
			extractedAtt = raw_input('Selection: ')
			
			# Check if attKey (extractedAtt) is supported input.
			try:
				attKey = int(extractedAtt)
			except ValueError:
				print('\nUnsupported input, try again...')
				continue
			
			# Check if attKey is within range.
			if (attKey < 0) or (attKey > 11):
				print('\nUnsupported input, try again...')
				continue

			# Find the length of the protocol's list.
			length = len(arpList)
			
			# The extracted attribute will be found by going through the protocol layers.
			# The attKey will be calibrated (if needed) to specify which attribute to print.
			if attKey >= 3:
				for i in range(length):
					packet = arpList[i]
					arp(packet, attKey - 3, printKey)
				break
			elif attKey >= 0:	
				for i in range(length):
					packet = arpList[i]
					eth(packet, attKey, printKey)
					
					# Separator	
					print('\n----------------------------------------')	
				break	
		elif filteredProtocol == 1:
			print(ethAttributes)
			print(ipAttributes)
			print(icmpAttributes)
			extractedAtt = raw_input('Selection: ')
			
			try:
				attKey = int(extractedAtt)
			except ValueError:
				print('\nUnsupported input, try again...')
				continue
			
			if (attKey < 0) or (attKey > 20):
				print('\nUnsupported input, try again...')
				continue
			
			length = len(icmpList)
			
			if attKey >= 16:	
				for i in range(length):
					packet = icmpList[i]
					icmp(packet, attKey - 16, printKey)
				break
			elif attKey >= 3:
				for i in range(length):
					packet = icmpList[i]
					ip(packet, attKey - 3, printKey)
					
					# Separator	
					print('\n----------------------------------------')	
				break
			elif attKey >= 0:	
				for i in range(length):
					packet = icmpList[i]
					eth(packet, attKey, printKey)
					
					# Separator	
					print('\n----------------------------------------')	
				break
		elif filteredProtocol == 2:
			print(ethAttributes)
			print(ipAttributes)
			print(tcpAttributes)
			extractedAtt = raw_input('Selection: ')
			
			try:
				attKey = int(extractedAtt)
			except ValueError:
				print('\nUnsupported input, try again...')
				continue
			
			if (attKey < 0) or (attKey > 33):
				print('\nUnsupported input, try again...')
				continue
			
			length = len(tcpList)
			
			if attKey >= 16:	
				for i in range(length):
					packet = tcpList[i]
					tcp(packet, attKey - 16, printKey)
				break
			elif attKey >= 3:
				for i in range(length):
					packet = tcpList[i]
					ip(packet, attKey - 3, printKey)
					
					# Separator	
					print('\n----------------------------------------')	
				break
			elif attKey >= 0:	
				for i in range(length):
					packet = tcpList[i]
					eth(packet, attKey, printKey)
					
					# Separator	
					print('\n----------------------------------------')	
				break
		elif filteredProtocol == 3:
			print(ethAttributes)
			print(ipAttributes)
			print(udpAttributes)
			extractedAtt = raw_input('Selection: ')
			
			try:
				attKey = int(extractedAtt)
			except ValueError:
				print('\nUnsupported input, try again...')
				continue
			
			if (attKey < 0) or (attKey > 19):
				print('\nUnsupported input, try again...')
				continue
			
			length = len(udpList)
			
			if attKey >= 16:	
				for i in range(length):
					packet = udpList[i]
					udp(packet, attKey - 16, printKey)
				break
			elif attKey >= 3:
				for i in range(length):
					packet = udpList[i]
					ip(packet, attKey - 3, printKey)
					
					# Separator	
					print('\n----------------------------------------')	
				break
			elif attKey >= 0:	
				for i in range(length):
					packet = udpList[i]
					eth(packet, attKey, printKey)
					
					# Separator	
					print('\n----------------------------------------')	
				break
				
def windowsExtract(filteredProtocol):
	# Establish the prompts for each protocol's attributes.
	ipAttributes = 	'0: Version\n1: Header Length\n2: Differentiated Services Code Point\n3: Explicit Congestion Notification\n4: Total Length\n5: Identification\n6: Flags\n7: Fragment Offset\n8: Time to Live\n9: Protocol\n10: Header Checksum\n11: Source Address\n12: Destination Address'
	icmpAttributes = '13: Type\n14: Code\n15: Checksum\n16: Identifier (If available)\n17: Sequence Number (If available)'
	tcpAttributes = '13: Source Port\n14: Destination Port\n15: Sequence Number\n16: Acknowledgment Number\n17: Data Offset\n18: Reserved\n19: NS Flag\n20: CWR Flag\n21: ECE Flag\n22: URG Flag\n23: ACK Flag\n24: PSH Flag\n25: RST Flag\n26: SYN Flag\n27: FIN Flag\n28: Window Size\n29: Urgent Pointer\n30: Checksum'
	udpAttributes = '13: Source Port\n14: Destination Port\n15: Length\n16: Checksum'
	
	# Attributes will be printed.
	printKey = 0
	
	# Repeated if incorrect input.
	while True:
		# Find the filtered protocol specified by the user.
		if filteredProtocol == 0:
			# Display the approriate attributes available from the filtered protocol.
			print(ipAttributes)
			print(icmpAttributes)
			extractedAtt = raw_input('Selection: ')
			
			# Check if attKey (extractedAtt) is supported input.
			try:
				attKey = int(extractedAtt)
			except ValueError:
				print('\nUnsupported input, try again...')
				continue
			
			if (attKey < 0) or (attKey > 17):
				print('\nUnsupported input, try again...')
				continue
				
			# Find the length of the protocol's list.
			length = len(icmpList)
			
			# The extracted attribute will be found by going through the protocol layers.
			# The attKey will be calibrated (if needed) to specify which attribute to print.
			if attKey >= 13:	
				for i in range(length):
					packet = icmpList[i]
					icmp(packet, attKey - 13, printKey)
				break
			elif attKey >= 0:
				for i in range(length):
					packet = icmpList[i]
					ip(packet, attKey, printKey)
					
					# Separator	
					print('\n----------------------------------------')	
				break
		elif filteredProtocol == 1:
			print(ipAttributes)
			print(tcpAttributes)
			extractedAtt = raw_input('Selection: ')
			
			try:
				attKey = int(extractedAtt)
			except ValueError:
				print('\nUnsupported input, try again...')
				continue
			
			if (attKey < 0) or (attKey > 30):
				print('\nUnsupported input, try again...')
				continue
			
			length = len(tcpList)
			
			if attKey >= 13:	
				for i in range(length):
					packet = tcpList[i]
					tcp(packet, attKey - 13, printKey)
				break
			elif attKey >= 0:
				for i in range(length):
					packet = tcpList[i]
					ip(packet, attKey, printKey)
					
					# Separator	
					print('\n----------------------------------------')	
				break
		elif filteredProtocol == 2:
			print(ipAttributes)
			print(udpAttributes)
			extractedAtt = raw_input('Selection: ')
			
			try:
				attKey = int(extractedAtt)
			except ValueError:
				print('\nUnsupported input, try again...')
				continue
			
			if (attKey < 0) or (attKey > 16):
				print('\nUnsupported input, try again...')
				continue
			
			length = len(udpList)
			
			if attKey >= 13:	
				for i in range(length):
					packet = udpList[i]
					udp(packet, attKey - 13, printKey)
				break
			elif attKey >= 0:
				for i in range(length):
					packet = udpList[i]
					ip(packet, attKey, printKey)
					
					# Separator	
					print('\n----------------------------------------')	
				break

def findMaxDiameter():
	# Find the maximum diameter of all the packets.
    diameterMax = max(diameterList)
    
    # Print the maximum diameter.
    print('Max Diameter: ' + str(diameterMax))

def findAverageDiameter():
	# Hold the sum and the count of the diameters.
    diameterSum = 0
    count = 0
    
    # Add all of the diameters together.
    for diameter in diameterList:
        diameterSum = diameterSum + diameter
        count = count + 1
        
    # Divide diameterSum by count to give average.
    diameterAverage = diameterSum / count
    print('Average Diameter: ' + str(diameterAverage))

def findAveragePacketSize():
	# Hold the sum and the count of the packet lengths.
    lengthSum = 0
    count = 0
    
    # Add all of the lengths together.
    for length in lengthList:
        lengthSum = lengthSum + length
        count = count + 1
        
    # Divide lengthSum by count to give average.
    lengthAverage = lengthSum / count
    print('Average Packet Size: ' + str(lengthAverage) + ' bytes')

def startSniff():
	try:
		while True:
			# Ask the user if they would like to begin the sniffer or not.
			decision = raw_input('Would you like to sniff the network? Y/N: ')
			
			# Y runs the rest of the application.
			# N exits the application.
			if (decision == 'Y') or (decision == 'y'):
				print('Sniffing, press Ctrl+c to stop...')
				break
			elif (decision == 'N') or (decision == 'n'):
				close()
			else:
				print('\nUnsupported input...')
	except KeyboardInterrupt:
		print('')
		close()

def startFilter():
	try:
		while True:
			# Ask the user if they would like to filter the packets or not.
			decision = raw_input('Would you like to filter the sniffed packets by protocol? Y/N: ')

			# Y runs the rest of the application.
			# N exits the application.
			if (decision == 'Y') or (decision == 'y'):
				print('Select a protocol...')
				return 0
			elif (decision == 'N') or (decision == 'n'):
				return 1
			else:
				print('\nUnsupported input...')
	except KeyboardInterrupt:
		print('')
		return 1

def startExtract():
	try:
		while True:
			# Ask the user if they would like to extract attributes or not.
			decision = raw_input('Would you like to extract a specific attribute? Y/N: ')
			
			# Y runs the rest of the application.
			# N exits the application.
			if (decision == 'y') or (decision == 'Y'):
				print('Select an attribute...')
				return 0
			elif (decision == 'N') or (decision == 'n'):
				return 1
			else:
				print('\nUnsupported input...')
	except KeyboardInterrupt:
		print('')
		return 1

def startCalculations():
	try:
		while True:
			# Ask the user if they would like to start calculations or not.
			decision = raw_input('Would you like to do some calculations? Y/N: ')
			
			# Y runs the rest of the application.
			# N exits the application.
			if (decision == 'y') or (decision == 'Y'):
				return 0
			elif (decision == 'N') or (decision == 'n'):
				return 1
			else:
				print('\nUnsupported input...')
	except KeyboardInterrupt:
		print('')
		return 1	

def close():
	try:
		# Exit the application.
		print('Goodbye.')
		time.sleep(1)
		sys.exit()
	except KeyboardInterrupt:
		sys.exit()

def sniff():
	# Ask the user to begin.
	startSniff()
		
	try:
		# If Linux, set up the raw socket the Linux way.
		# If Windows, set up the raw socket the Windows way.
		# If not Linux or Windows, close the application.
		if os == linux:
			# Create the raw socket.
			sock = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
			
			# Sniff packets. Will loop until user presses Ctrl+c.
			while True:	
				# Recieve the packets in the network.
				# Packet will be a tuple, use the first element in the tuple.
				packet = sock.recvfrom(65565)
				packet = packet[0]				
				
				unpackAndDisplay(packet)
				unpackAndSave(packet)
				
			# Close the socket.
			sock.close()
		elif os == windows:
			# The public network interface.
			HOST = socket.gethostbyname(socket.gethostname())

			# Create a raw socket and bind it to the public interface.
			sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
			sock.bind((HOST, 0))

			# Include IP headers
			sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

			# Receive all packages.
			sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
			
			# Sniff packets. Will loop until user presses Ctrl+c.
			while True:	
				# Recieve the packets in the network.
				# Packet will be a tuple, use the first element in the tuple.
				packet = sock.recvfrom(65565)
				packet = packet[0]
					
				unpackAndDisplay(packet)
				unpackAndSave(packet)	
				
			# Disable promiscuous mode.	
			sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
			
			# Close the socket.
			sock.close()
		else:
			print('The OS you are running is not supported.')
			close()   				
	except socket.error, msg:
		print('Socket could not be created. \nError code: ' + str(msg[0]) + '\nMessage: ' + msg[1])
		close()
	except KeyboardInterrupt:
		print('\nSniffing stopped.')

def filterAndExtract():
	# Ask the user to filter by protocol.
	# If 0, filter.
	# If not 0, move on.
	if startFilter() == 0:
		try:
			# If Linux, filter Linux's supported protocols, then extract.
			# If Windows, filter Window's supported protocols, then extract.
			if os == linux:
				# Ask the user to extract an attribute.
				# If 0, extract.
				# If not 0, move on.
				protocol = linuxFilter()
				if 	startExtract() == 0:
					linuxExtract(protocol)
			elif os == windows:
				# Ask the user to extract an attribute.
				# If 0, extract.
				# If not 0, move on.
				protocol = windowsFilter()
				if 	startExtract() == 0:
					windowsExtract(protocol)
		except KeyboardInterrupt:
			print('\nFiltering and extracting stopped.')

def calculate():
	# Ask the user to do some calculations.
	# If 0, calculate.
	# If not 0, move on.
	if startCalculations() == 0:
		try:
			findMaxDiameter()
			findAverageDiameter()
			findAveragePacketSize()
		except KeyboardInterrupt:
			print('\nCalculations stopped.')
	
def main():	
	while True:
		sniff()
		filterAndExtract()
		calculate()
	close()

main()
