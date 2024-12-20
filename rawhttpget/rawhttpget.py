#! /usr/bin/env python
import socket
import sys
from random import randint
import fcntl
from struct import pack, unpack, calcsize
import subprocess, shlex, re
import binascii
import time
#import gc

def getSourceAddr():
	s1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s1.connect(("david.choffnes.com",80))
	source_ipaddr = s1.getsockname()[0]
	s1.close()
	return source_ipaddr

def main(argv):

	if len(sys.argv) < 2 or len(sys.argv) > 2:
		print "Please enter the argument as specfied in the README"
		sys.exit(0)

	url = sys.argv[1]
	index = url.find("://")
	if index == -1:
		print "please provide a url"
		sys.exit(0)
	index1 = index + 3
	index2 = url.find("/",index1)
	
	if index2 == -1:
		url2 = "/"
		hostname = url[index1:]	
	else:
		url2 = url[index2:]
		hostname = url[index1:index2]
	
	
	#print "hostname--url--"+hostname+","+url2
	source_address = getSourceAddr()
	dest_address = socket.gethostbyname(hostname)
	receiveddata = ""
	try:
		s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
	except socket.error, msg:
		print "Error creating socket" + str(msg[0])
		sys.exit()            	
	s.bind(('eth0',socket.SOCK_RAW)) 
	#destination_mac,sender_hw_address = arp()
	TCP_source_port = randint(10000,65535)
	random_sequence = randint(0,90000)
	destination_mac,sender_hw_address = arp(s,source_address)
	try:
		s2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
	except socket.error, msg:
		print "Error creating socket" + str(msg[0])
		sys.exit()            	
	s2.bind(('eth0',socket.SOCK_RAW)) 
	seq,ack = build_packet(s2,random_sequence,0,0,1,54321,TCP_source_port,0,"",0,0,hostname,destination_mac,sender_hw_address,source_address)
	rec_data(s2,dest_address,seq,ack,TCP_source_port,hostname,url2,receiveddata,destination_mac,sender_hw_address,source_address)
#	gc.collect()

def arp(s,source_address):

	frame = 'eth0'
	hardware_type = 1
	protocol_type = 0x0800
	hardware_address_length = 6
	protocol_address_length = 4
	operation =  1
	s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	#r = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    	mac_addr = fcntl.ioctl(s2.fileno(), 0x8927,  pack('256s', frame[:15]))[18:24]
    	#hardware_address = ':'.join(['%02x' % ord(char) for char in info[18:24]])
	#print hardware_address
	#sender_hw_address = hardware_address
	sender_hw_address = mac_addr
	#print "info+++++++++++",len(info)
	byte_value = int('FF',16)
	target_hardware_address = pack('!6B',byte_value,byte_value,byte_value,byte_value,byte_value,byte_value)
	#sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
	#sock.bind(('eth0',socket.SOCK_RAW)) 
	#sock = sock.getsockname()[4]
	#source_address = getSourceAddr()	
	source_protocol_address = socket.inet_aton(source_address)
#	target_hardware_address = hardware_address	
	strs =  subprocess.check_output(shlex.split('ip r l'))
	match_string = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
	target_protocol_address = re.search('default via ' + match_string, strs).group(1)
	#print "++++",target_protocol_address
	#print gateway
	
	arp_data = pack('!HHBBH6s4s6s4s',hardware_type,protocol_type,hardware_address_length,protocol_address_length,operation,sender_hw_address,
		source_protocol_address,
		target_hardware_address,
		socket.inet_aton(target_protocol_address))	

	destination_mac = build_ethernet_frame(s,sender_hw_address,target_hardware_address,arp_data)
	#built_frame = build_frame(destination_mac,source_mac,ipdata)
	
	return destination_mac,sender_hw_address


	
def build_ethernet_frame(sock,source_addr,dest_addr,data):	
	
	eth_frame = pack('!6s6sH',dest_addr,source_addr,0x0806)
	total_eth_frame = ''.join([eth_frame,data])	
	sock.send(total_eth_frame)
	while 1: 	
		recvd = sock.recv(65355)
		#print recvd
		ethernet_header_length = recvd[:14]
		extract_ethernet_header = unpack('!6s6sH',ethernet_header_length)
		#print "print madappa rajaa",extract_ethernet_header
		source_mac = ':'.join(['%02x' % ord(char) for char in extract_ethernet_header[0]])
		#print "source:",source_mac
		destination_mac = ':'.join(['%02x' % ord(char) for char in extract_ethernet_header[1]])
		#print "destination:",destination_mac
		#print "Eth type:",extract_ethernet_header[2]
		#print "source and dest",extract_ethernet_header[0],extract_ethernet_header[1]		
		type_of_message,gateway_mac = extract_arp(recvd)
		if extract_ethernet_header[2] == 2054:
			if type_of_message == 2:
				return gateway_mac
				sock.close()		
				break

def build_frame(ipdata,s,destination_mac,sender_hw_address):

	frame = pack('!6s6sH',destination_mac,sender_hw_address,0x0800)
	final_frame = ''.join([frame,ipdata])	
	return final_frame

def extract_arp(reply):
	
	arp_reply = unpack('!HHBBH6s4s6s4s',reply[14:42])
	#print "arp_____data_____",arp_reply		
	#print "arp type",arp_reply[4]
	type_of_message = arp_reply[4]
	#destination_mac = ':'.join(['%02x' % ord(char) for char in arp_reply[5]])
	destination_mac = pack('256s', arp_reply[5])
	destination_mac_visual = ':'.join(['%02x' % ord(char) for char in arp_reply[5]])
	#print "gateway address",destination_mac_visual
	if type_of_message == 2: 
		#destination_mac = ':'.join(['%02x' % ord(char) for char in arp_reply[5]])
		destination_mac = pack('256s', arp_reply[5])
	#	print "Gateway MAC address:",destination_mac
		return type_of_message,destination_mac
	return type_of_message,destination_mac					
	
	
		

	

	

def build_packet(s,seq,ack,ackflag,synflag,pid,source_port,psh,data,dataflag,finflag,hostname,destination_mac,sender_hw_address,source_address):

	
	dest_address = socket.gethostbyname(hostname)
	source_ipaddr = socket.inet_aton(source_address)	
	destination_ipaddr = socket.inet_aton(dest_address)
	#Building Elements of TCP packet
	TCP_source_port = source_port
	TCP_destination_port = 80
	TCP_seq_no = seq 
	TCP_ack_no = ack 
	#print "sender side seq,ack",TCP_seq_no,TCP_ack_no
	TCP_checksum = 0
	TCP_FIN = finflag
	TCP_SYN = synflag
	TCP_RST = 0 
	TCP_PSH = psh
	TCP_ACK = ackflag
	TCP_URG = 0
	TCP_controlbits = TCP_FIN + (TCP_SYN * (2 ** 1)) + (TCP_RST * (2 ** 2)) + (TCP_PSH * (2 ** 3)) + (TCP_ACK * (2 ** 4)) + (TCP_URG * (2 ** 5))
	TCP_urgent_ptr = 0
	TCP_data_offset = 5
	TCP_data_res = (TCP_data_offset * (2 ** 4)) + 0
	TCP_window_size = socket.htons(5840)    
	tcp_header2 =  pack('!HHLLBBHHH',TCP_source_port,TCP_destination_port,TCP_seq_no,TCP_ack_no,TCP_data_res,TCP_controlbits,TCP_window_size,TCP_checksum,TCP_urgent_ptr)
    
        
	#Building pseudo TCP Header
	TCP_source_address = source_ipaddr
	TCP_destination_address = destination_ipaddr
	reserved = 0
	pseudo_header_protocol = 6
	if dataflag == 1:
		total_length = len(tcp_header2) + len(data)
	else:		
		total_length = len(tcp_header2)
	pseudo_header = pack('!4s4sBBH',TCP_source_address,TCP_destination_address,reserved,pseudo_header_protocol,total_length)
	#pseudo_header = pseudo_header + tcp_header1 + url
	if dataflag == 1:
		pseudo_header = pseudo_header + tcp_header2 + data   
	else:
		pseudo_header = pseudo_header + tcp_header2
	TCP_checksum = compute_checksum(pseudo_header)

	#print "seq,ack",TCP_seq_no,TCP_ack_no
	tcp_header1 =  pack('!HHLLBBH',TCP_source_port,TCP_destination_port,TCP_seq_no,TCP_ack_no,TCP_data_res,TCP_controlbits,TCP_window_size)
	tcp_checksum_header = pack('H',TCP_checksum)
	tcp_tail = pack('!H',TCP_urgent_ptr)
	tcp_header = tcp_header1 + tcp_checksum_header + tcp_tail
	#packet = ip_header + tcp_header + urlwire

	#Building Elements of IP datagram
	dest_address = socket.gethostbyname(hostname)
	version = 4
	IHL = 5
	version_ihl = (version * (2 ** 4)) + IHL
	checksum = 0
	total_length = 0
	ttl = 255 
	protocol = 6
	source_ipaddr = socket.inet_aton(source_address)

	destination_ipaddr = socket.inet_aton(dest_address)

	packet_id = randint(10000,65000)
	fragment_offset = 0
	type_of_service = 0


	ip_header = pack('!BBHHHBBH4s4s',version_ihl,type_of_service,total_length,packet_id,fragment_offset,ttl,protocol,checksum,source_ipaddr,destination_ipaddr)
	#print ip_header
        checksum_new = compute_checksum(ip_header)
	if dataflag == 1:
		total_length = IHL * 4 + len(tcp_header) + len(data)
	else:
		total_length = IHL * 4 + len(tcp_header)
	#ip_header = pack('!BBHHHBBH4s4s',version_ihl,type_of_service,total_length,packet_id,fragment_offset,ttl,protocol,checksum_new,source_ipaddr,destination_ipaddr)
	ip_header1 = pack('!BBHHHBB',version_ihl,type_of_service,total_length,packet_id,fragment_offset,ttl,protocol)
	ip_header2 = pack('H',checksum_new)
	ip_header3 = pack('!4s4s',source_ipaddr,destination_ipaddr)
	ip_header = ip_header1 + ip_header2 + ip_header3
	

	
	if dataflag == 1:
		packet = ip_header + tcp_header + data
	else:
		packet = ip_header + tcp_header
	final_frame = build_frame(packet,s,destination_mac,sender_hw_address)
	s.send(final_frame) 
	return TCP_seq_no, TCP_ack_no


#Calculating TCP Checksum
def compute_checksum(data):
	initial_sum = 0    
	length = len(data)
	i= 0
	while (length > 1) :
		w = ord(data[i]) + (ord(data[i+1]) << 8 )
		initial_sum = initial_sum + w
		i = i + 2
		length = length - 2
	if length == 1:
		initial_sum = initial_sum + ord(data[i])
	initial_sum = (initial_sum>>16) + (initial_sum & 0xffff);
	initial_sum = initial_sum + (initial_sum >> 16);
	initial_sum = ~initial_sum & 0xffff
	return initial_sum



#Unpacking procedure
def unpack_tcp_ip(r):
	recv_data = ''
	while True:	
		recv_data = r.recv(65535)

		ethernet_header_length = recv_data[:14]
		eth_header = unpack('!6s6sH',ethernet_header_length)
		#print "eth_proto",eth_header[2]
		if eth_header[2] ==  0x0800:
			break


	ip_packet = recv_data[14:14+20]
	unpacked_data = unpack("!BBHHHBBH4s4s",ip_packet)
	rprotocol = unpacked_data[6]
	#print "ip --protocol",rprotocol
 	rsource_address = socket.inet_ntoa(unpacked_data[8]) 
	rdestination_address = socket.inet_ntoa(unpacked_data[9])   
	#	print "source and destination",rsource_address,rdestination_address
	rversion_ihl = unpacked_data[0]
	rihl = rversion_ihl & 0xF
	#print "header length",rihl
	ipheader_length = rihl * 4
	total_length = unpacked_data[2]
	#tcp_header_prev = recv_data[14:]
	#tcp_header = tcp_header_prev[ipheader_length:ipheader_length+20]	
	tcp_header_len = 14 + ipheader_length
	tcp_header = recv_data[tcp_header_len : tcp_header_len+20]
	
 	

	rtcp = unpack('!HHLLBBHHH',tcp_header)
	rseq = rtcp[2]
	rack = rtcp[3]

	data_offset = rtcp[4]
	flags = rtcp[5]
	flags = bin(flags)
	flag_str = str(flags)
	len_flag = len(flag_str)
	fin_flag = flag_str[len_flag-1:]
	#print "flag",flag_str
	#print "fin flag",fin_flag
	tcp_header_length = data_offset >> 4
	header_size =  ipheader_length + (tcp_header_length * 4)
	new_header_size = len(ethernet_header_length) + header_size
	data_offset = 14 + ipheader_length + tcp_header_length * 4
	data = recv_data[data_offset:]	
	#print "unpacked data",data
	#print "in unpacking",data
	return rseq,rack,data,fin_flag
	


#Receiving Data
def rec_data(s,dest_address,seq,acq,TCP_source_port,hostname,url,receiveddata,destination_mac,sender_hw_address,source_address):
	
	try:
		r= socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.ntohs(0x800))
	except socket.error, msg:
		print "Error in creating receive socket" + str(msg[0])
		sys.exit()
	
	#source_address = getSourceAddr()
	#print "======"
	r.bind(('eth0',socket.SOCK_RAW)) 
	#r.bind((source_address,65535))
	rack = -900
	#print "rseq,rack",rseq, rack	
	while rack != seq + 1:
		#print "inside while"
		#recv_data = r.recv(65355)
		rseq,rack,data,fin = unpack_tcp_ip(r)
		#print "rseq||||||||||||rack",rseq,rack
	syn = 0
	ackfield = 1
	seq = rack
	ack = rseq + 1
	psh = 0
	dataflag = 0
	pid = randint(10000,65000)
	new_seq,new_ack = build_packet(s,seq,ack,ackfield,syn,pid,TCP_source_port,psh,"",dataflag,0,hostname,destination_mac,sender_hw_address,source_address)
	
	#Sending GET request
	
	psh = 1
	ackfield = 1
	dataflag = 1
	pid = randint(10000,65000)
	data = "GET "+url+" HTTP/1.0\nHost: "+hostname+"\r\n\r\n"
	#print data
	new_seq,new_ack = build_packet(s,seq,ack,ackfield,syn,pid,TCP_source_port,psh,data,dataflag,0,hostname,destination_mac,sender_hw_address,source_address)
	new_rec_ack = seq + len(data)
	cwnd = 1
	
	#Check for HTTP Response

	nack = -100
	while new_rec_ack != nack:		
		#print "here"
		#http_data = r.recv(65355)	
		nseq,nack,httpdata,fin= unpack_tcp_ip(r)
		#print "data nic---------------------------------------------------------------",httpdata  #

	nack = -100	
	while new_rec_ack != nack:						
		nseq,nack,httpdata,fin= unpack_tcp_ip(r)			
		

	
	
	if httpdata.find("HTTP/1.1 200 OK") >= 0:	

		#print httpdata
		len_new_rec_data = len(httpdata)
		receiveddata = receiveddata + httpdata 

		# we have got the 200 OK responce right the below step requests for next segment
		send_new_ack = nseq + len(httpdata)
		#print nseq
		#print len(httpdata)
		new_seq,new_rack = build_packet(s,nack,send_new_ack,ackfield,0,pid,TCP_source_port,0,"",0,0,hostname,destination_mac,sender_hw_address,source_address)

	
	 
		while 1:
			nseq = -1	
			timeout = 1
			start_time = time.time()			
			while send_new_ack != nseq:
				#print "-----"
				if timeout < (time.time() - start_time):
					new_seq,new_rack = build_packet(s,new_rec_ack,send_new_ack,ackfield,0,pid,TCP_source_port,0,"",0,0,hostname,destination_mac,sender_hw_address,source_address)	
					#print "TIMEOUT!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
					cwnd = 1
					start_time = time.time()
	
				else:					
					#print "inside while",recv_new_data		
						#continue					
						#print "else part",recv_new_data						
					nseq,new_rec_ack,new_rec_data,fin = unpack_tcp_ip(r)
					cwnd = cwnd + 1
					#print "seq--ack--expected_ack",nseq,new_rec_ack,send_new_ack
				
			

			receiveddata = receiveddata + new_rec_data 
			#print receiveddata
			len_new_rec_data = len(new_rec_data)
			send_new_ack = nseq + len_new_rec_data
			pid = randint(10000,65000)
			
			if fin == '1':
				build_packet(s,new_rec_ack,nseq+1,ackfield,0,pid,TCP_source_port,0,"",0,1,hostname,destination_mac,sender_hw_address,source_address)
				s.close()				
				break			
				
			else:
				new_seq,new_rack = build_packet(s,new_rec_ack,send_new_ack,ackfield,0,pid,TCP_source_port,0,"",0,0,hostname,destination_mac,sender_hw_address,source_address)
		r.close()		
		#print "++++++++++++++++",receiveddata
		offset1 = receiveddata.find("Content-Type")
		offset = receiveddata.find("\n",offset1)
		logfile = receiveddata[offset+3:]
		urllength = len(url)
		reversedurl = url[::-1]
		offset = reversedurl.find("/") 
		if offset == 0:
			filename = "index.html"
		else:
			filename = url[urllength-offset:]
		#print filename

		try:
			f=open(str(filename),"w")
		except IOError:
			f=open(str(filename),"w")		
		f.write(logfile)
		f.close()
		#print len(receiveddata)
		
	else:	
		retry = 2
		count = 0
		if count <= retry:
			main(sys.argv[0:])
			count = count + 1			
		else:	
			print "HTTP 200 Response was not received. Please Try again or the request page is not available at this time"
			sys.exit(0)	
	
	


if __name__ == "__main__":
	main(sys.argv[0:])