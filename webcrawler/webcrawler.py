#! /usr/bin/env python
import socket
import re
import sys
								#import essential modules for sockets, regular expressions and parsing commandline arguements
def main(argv):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)	# Create a socket s
    hostname = "cs5700sp15.ccs.neu.edu"				# Initialize host
    username =  sys.argv[1] 					# Get the username from the commandline
    password =  sys.argv[2]					# Get the password from the commandline
    host = socket.gethostbyname(hostname)			# Get the ip address of the hostname
    port = 80							# Initialize port to 80
    s.connect((host, port))					# Connect the socket to the specified host and port
    s.sendall("GET /accounts/login/ HTTP/1.1\nHost: cs5700sp15.ccs.neu.edu\nConnection: keep-alive\r\n\r\n")
    page = s.recv(10000)					# Receive the contents of the login page
    csrf_token_position = page.find('csrfmiddlewaretoken')	# Find the initial position of csrfmiddlewaretoken
    csrf_token = page.find('value', csrf_token_position + 1)	# Find the position of field value
    csrf_value = page[csrf_token + 7 : csrf_token + 39]		# Extract the actual value of the csrf token
    # send the HTTP Post message by specifying the required headers and also by specifying the retrieved username and password(from commandline) in the body
    s.sendall("POST /accounts/login/ HTTP/1.1\nHost: cs5700sp15.ccs.neu.edu\nConnection: keep-alive\nContent-Length: 109\nCookie: csrftoken="+csrf_value+";\r\n\r\nusername="+ username + "&password="+ password + "&csrfmiddlewaretoken="+csrf_value+"&next=%2Ffakebook%2F\r\n")
    page1 = s.recv(1000000)					# Receive the response
    position = page1.find("sessionid=")				# Find the sessionid in the response
    session_id =  page1[position+10:position+42]		# Parse the sessionid in the response
    crawl_fakebook("/fakebook/",s,session_id,csrf_value)	# Call the crawl_fakebook procedure by passing in the seed page, socket and sessionid



def get_content(path,s,session_id,csrf_value):			# This procedure retrieves the content of the given page
    s.sendall("GET "+ path +" HTTP/1.1\nConnection: keep-alive\nHost: cs5700sp15.ccs.neu.edu\nCookie: csrftoken="+csrf_value+" ; sessionid="+session_id+";"+"\r\n\r\n")				     # Sends HTTP Get message to retrieve the contents of the given page.(sessionid is included) 
    new_page = s.recv(1000000)
    return new_page						# returns the content of the given page


def get_target(login_page):					# This procedure retrieves the first link from the given page
    start_link = login_page.find('<a href=')			# Finds '<a href=' and stores it's position in a variable start_link
    if start_link == -1:					# Returns none if no such link has been found
        return None, 0
    start_position = login_page.find('"', start_link)		# Finds the position of the opening quote and assigns it to start_position
    end_position = login_page.find('"', start_position + 1)	# Finds the position of the closing quote and assigns it to end_position
    url = login_page[start_position + 1:end_position]		# Obtains the url based on the start and end position
    return url,end_position					# returns the url and the end_position
	

def get_all_links(login_page):					# This procedure retrieves all the links from the given page
        links = []						# Initialise the list of links to empty
        while True:
                url, endpos = get_target(login_page)		# Calls the get_target procedure until the get_target returns None else breaks
                if url:						
                        links.append(url)			# Appends the obtained link to the list of links
                        login_page = login_page[endpos:]	# login_page is now only the content from the returned end_pos
                else:
                        break
        return links


def crawl_fakebook(home,s,session_id,csrf_value):		# this procedure explores all the pages by maintaining a tocrawl and a crawled list

    tocrawl = [home]						# Initialise tocrawl to the seed page
								# initialise crawled to the pages which are not to be crawled
    crawled = ["mailto:choffnes@ccs.neu.edu","http://www.northeastern.edu","http://www.ccs.neu.edu/home/choffnes/"]
    secret_count = 0						# Initialise secret_count to 0
    count = 0							# Initialise page counter to 0
    while tocrawl and secret_count < 6:				# Loop while there are pages to be explored in tocrawl and the secret count is less than 6
        count = count + 1					# Increment the page counter
        page = tocrawl.pop()					# Pop the page that is to be explored
        if page not in crawled:					# Explore the page if it's not already in the list of crawled pages
            content = get_content(page,s,session_id,csrf_value)		# Obtain the content of the page and initialise it to content
            status_code = re.findall(r"\D(\d{3})\D", content)   # Find the status code from the obtained content	     

            if status_code[0] == '500':				# If the status code is 500 
               # print "---------------------------------500 error"
								# Create a new socket connection and make the request again
                sk = socket.socket(socket.AF_INET,socket.SOCK_STREAM)	
                sk.connect(("cs5700sp15.ccs.neu.edu",80))
                sk.sendall("GET "+ page +" HTTP/1.1\nHost: cs5700sp15.ccs.neu.edu\nCookie: csrftoken="+csrf_value+" ; sessionid="+session_id+";"+"\r\n\r\n")
                new_page = sk.recv(1000000)
                s=sk						# Initialise the new socket object to the old socket variable

            if status_code[0] == '301':				# if the status code is 301
               # print "---------------------------------300 error"
								
                location = content.find("Location")		# Find the Location field from response
                profile_number = content.find("/fakebook/",location+1)	# Obtain the profile number from the url in response
                end_of_line = content.find(" ",profile_number)		# The position of the end of profile number is assigned to end_position
                new_url = content[profile_number:end_of_line]		# assign the obtained url to new url and make the request again
                s.sendall("GET "+ new_url +" HTTP/1.1\nHost: cs5700sp15.ccs.neu.edu\nCookie: csrftoken="+csrf_value+" ; sessionid="+session_id+";"+"\r\n\r\n")
                new_page = s.recv(1000000)			# Receive the content and assign it to new_page

            if status_code[0] == "404" or status_code[0] == "403":
                 crawled.append(page)				# If status code is 404 or 403 just add it to the list of crawled pages

            if status_code[0] != "404" or status_code[0] != "403": # If status code is is not 403 or 404                                                                                                  
                links_from_page = get_all_links(content)	# Get all the links from the page and assign it to links_from_page
                union(tocrawl, links_from_page,crawled)		# Eliminate duplicate pages by doing a union
                crawled.append(page)				# Append the explored page to the crawled list
                sk = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                sk.connect(("cs5700sp15.ccs.neu.edu",80))	
                s=sk						# Create a new socket connection an assign the new socket object to the old socket variable
                secret_position = content.find("FLAG")		# Find the position of "FLAG" and assign it to secret_position
                   
                if secret_position >= 0:			# If there is a secret_position, extract the 64 character secret and increment the secret_count
                    secret = content[secret_position + 6:secret_position + 70] 
                    secret_count = secret_count + 1
                    print secret
                    
def union(tocrawl, obtained_links,crawled):			# Procedure that performs a union of the obtained_links and tocrawl list
        for e in obtained_links:
                if e not in tocrawl and e not in crawled:
                         tocrawl.append(e)			# Append to tocrawl only if the obtained links are not in tocrawl and crawled list
        return tocrawl
    
    
if __name__ == "__main__":
    main(sys.argv[0:])