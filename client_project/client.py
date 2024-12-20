#! /usr/bin/env python
import socket 						   	# Import the essential modules
import re							
import sys
import ssl					        	 
def main(argv):	
	s = socket.socket()					# Creates a socket object
	n = 1								
	if sys.argv[n] == "-p":					# Checks if the argument provided is "-p"
		if sys.argv[n+1].isdigit():			# validates the port number
			port = sys.argv[n+1]
			if sys.argv[n+2] == "-s":		# Checks if the argument provided is "-s"
				connectWithSSL(port,s,n+3)	# Calls the procedure which implements SSL sockets
			else:
				port = sys.argv[n+1]
				connectWithoutSSL(port,s,n+2)	# Calls the straight forward procedure without SSL
		else:
			print "Provide valid port number"	# Exits if a valid port number is not provided
			sys.exit()				
								

	elif sys.argv[n] == "-s":				# Checks if the first argument is "-s"
		if sys.argv[n+1] == "-p":			# Checks if the second argument is "-p"
			if sys.argv[n+2].isdigit(): 		
				port = sys.argv[n+2]
				connectWithSSL(port,s,n+3)	# Calls the procedure with SSL implementation
			else:
				print "provide port number"
				sys.exit()			
		else:
			port = 27994
			connectWithSSL(port,s,n+1)		# If the port number is not provided,the connection is made to the default
                                                                # port with SSL implementation
	else:
		port = 27993
		connectWithoutSSL(port,s,n)			# Implement socket without SSL with the default port number

def connectWithoutSSL(port,s,n):				# Procedure that implements socket without SSL
	
	if sys.argv[n] == 'cs5700sp15.ccs.neu.edu':		# Validates host
                host = sys.argv[n]
                n = n + 1
        else:
                print "not a valid host name"			# Exits if a valid host name is not provided
                sys.exit()   
        neuid = sys.argv[n]					
        if neuid[0:2] != '00' or not (neuid.isdigit()):		# validates NEU ID 
                print "not a valid NEU ID"			
                sys.exit()					# Exits if a valid NEU ID is not provided
        data = 'cs5700spring2015 HELLO ' + neuid + ' \n'	# Sets data according the specified format
	s.connect((host,int(port)))				# Makes a socket connection to the host via the specified port
	s.send(data)						# Sends the data to the server using the socket connection
	received = s.recv(1024)					# Sets 1024 bytes to receive data from the server
	q = re.match("\d+[ ][*+-/][ ]\d+", received[24:])	# Matches the expression received using regex and assigns it to a variable
	assert received[17:23] == 'STATUS' and q and received[0:16] == 'cs5700spring2015' # Asserts an error if the received message is not valid
	parsed_string = received[24:]				
	result = eval(parsed_string)				# Evaluates the received mathematical expression
	solution = 'cs5700spring2015 ' + str(result) + '\n'	# Set the solution according to the format
	s.send(solution)					# Sends the solution to the server
	received2 = s.recv(1024)				


	while received2[-4]!= 'B':				# Runs the loop until the 4th character from the end of the received message is "B"
		parsed_string = received2[24:]
		assert received2[17:23] == 'STATUS' and q and received2[0:16] == 'cs5700spring2015' 
		result = eval(parsed_string)
		solution = 'cs5700spring2015 ' + str(result) + '\n'
		s.send(solution)
		received2 = s.recv(1024)
		if received2[-4] == 'B':			
			secret =  received2[17:81]
			print secret
			s.close()				# Terminates the loop by printing the secret from the BYE message

def connectWithSSL(port,s,n):					# Procedure with SSL implementation, Functionality is pretty much the same except that 
                                                                # this implements SSL
	if sys.argv[n] == 'cs5700sp15.ccs.neu.edu':
                host = sys.argv[n]
                n = n + 1
        else:
                print "not a valid host name"
                sys.exit()
        neuid = sys.argv[n]
        if neuid[0:2] != '00' or not (neuid.isdigit()):
                print "not a valid NEU ID"
                sys.exit()
        
	data = 'cs5700spring2015 HELLO ' + neuid + ' \n'
	s.connect((host, int(port)))
	ssl_sock = ssl.wrap_socket(s,cert_reqs=ssl.CERT_NONE,ca_certs=None) # wraps the socket object using SSL Wrapper
	ssl_sock.write(data)				         # Sends the data using the SSL wrapper object
	received = ssl_sock.read(1024)				 # Receives the data using the secure SSL channel that was created	    
	q = re.match("\d+[ ][*+-/][ ]\d+", received[24:])
	assert received[17:23] == 'STATUS' and q and received[0:16] == 'cs5700spring2015'
	parsed_string = received[24:]
	result = eval(parsed_string)
	solution = 'cs5700spring2015 ' + str(result) + '\n'
	ssl_sock.write(solution)
	received2 = ssl_sock.read(1024)

	while received2[-4]!= 'B':
        	parsed_string = received2[24:]
		assert received2[17:23] == 'STATUS' and q and received2[0:16] == 'cs5700spring2015'
        	result = eval(parsed_string)
	        solution = 'cs5700spring2015 ' + str(result) + '\n'
        	ssl_sock.write(solution)
	        received2 = ssl_sock.read(1024)
		if received2[-4] == 'B':
                        secret =  received2[17:81]
                        print secret             
	received_final = ssl_sock.read(1024)

if __name__ == "__main__":
    main(sys.argv[0:])




	
	