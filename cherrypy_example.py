#!/usr/bin/python
""" MainFile.py

    COMPSYS302 - Software Design - Python Project
    Author: Savi Mohan (smoh944@auckland.ac.nz)
    Last Edited: 11/06/2017

    This program uses the CherryPy web server (from www.cherrypy.org).
"""
# Requires:  CherryPy 3.2.2  (www.cherrypy.org)
#            Python  (We use 2.7)

# The address we listen for connections on
listen_ip = "0.0.0.0"
listen_port = 10001
SALT = "COMPSYS302-2017"
DB_USER_DATA = "sqliteDatabase.db"


import cherrypy
import hashlib
import urllib

import urllib2
import sqlite3
import json
import time
import os #used to figure out what operating system this is running on
import webbrowser
import socket

import thread
import base64
import markdown
from operator import xor

class MainApp(object):
			
	def getLocation(self,ip):
		"""Determines the location of the client based on the ip"""
		if (('130.216.' in ip)or('10.103.' in ip)or('10.104.' in ip)):
			return '0'	#Uni Desktop
		elif(('172.23.' in ip)or('172.24.' in ip)):
			return '1'	#Uni WiFi
		else:
			return '2'	#Rest of World
	
	def getIP(self):
		"""Determines the ip adddress of the client"""
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.connect(("8.8.8.8",80))
		internalIP = s.getsockname()[0] #get internal ip
		s.close()
			
		externalIP = (urllib2.urlopen(urllib2.Request('http://ident.me'))).read().decode('utf8') #retrieves external ip	
		
		location = self.getLocation(internalIP) #get location value that corresponds to the internal ip
		
		if((location == '0')or(location == '1')):
			print('The IP of this client is: '+str(internalIP))
			return str(internalIP)
		else:
			print('The IP of this client is: '+str(externalIP))
			return str(externalIP)
	
	def clearRateRequestTable(self):
		"""Clears the requestNumbers column in the RateRequest table to 0"""
		conn = sqlite3.connect(DB_USER_DATA)		
		# Once we have a Connection, we can create a Cursor object and call its execute() method to perform SQL commands
		c = conn.cursor()
		
		c.execute("UPDATE RequestRate SET requestsNumber = 0")
		
		conn.commit()
		conn.close()
		
	
	def checkIfRateLimited(self,requestor=None):
		"""Takes in a username and determines whether that user has exceeded the allowable request rate"""
		rateLimited = False
		
		try:
			if (requestor == cherrypy.session['username']): #Don't ratelimit the session user
				return rateLimited
		except:
			pass
			
		conn = sqlite3.connect(DB_USER_DATA)			
		# Once we have a Connection, we can create a Cursor object and call its execute() method to perform SQL commands
		c = conn.cursor()
		
		try:			
			if(not(requestor == None)):
				c.execute('SELECT * FROM RequestRate WHERE (requestor=? )', (requestor,))
				data = c.fetchone()
				
				if data is None: #Insert requestor into table if they aren't already on it			
					c.execute('INSERT INTO RequestRate (requestor,requestsNumber) VALUES (?,?)', (requestor,1))
				else:
					c.execute('''UPDATE RequestRate SET requestsNumber = ? WHERE requestor = ?''',(data[2]+1, requestor))	
					if(data[2]>8): #if the number of requests for this user exceeds 8, then rate limit them
						rateLimited = True
		except:
			pass
		
		conn.commit()
		conn.close()

		return rateLimited	
		
		
		
	def createRequestRateTable():
		"""Creates a table to monitor the number of requests from users"""
		conn = sqlite3.connect(DB_USER_DATA)		
		
		# Once we have a Connection, we can create a Cursor object and call its execute() method to perform SQL commands
		c = conn.cursor()
		
		c.execute('''CREATE TABLE IF NOT EXISTS RequestRate (id INTEGER PRIMARY KEY, requestor TEXT, requestsNumber INTEGER)''')
		
		conn.commit()
		conn.close()	
	
	def createClientProfilesTable():
		"""Creates a table to store user profile details"""
		conn = sqlite3.connect(DB_USER_DATA)
				
		# Once we have a Connection, we can create a Cursor object and call its execute() method to perform SQL commands
		c = conn.cursor()
		
		c.execute('''CREATE TABLE IF NOT EXISTS ClientProfiles (id INTEGER PRIMARY KEY, profile_username TEXT, fullname TEXT, position TEXT, description TEXT, location TEXT, picture TEXT, encoding TEXT, encryption TEXT, decryptionKey TEXT)''')
		
		conn.commit()
		conn.close()
	
	def populateClientProfilesTable():
		"""Updates the ClientProfiles table with usernames from the login server's listUsers api"""
		serverUsersRequest = urllib2.Request('http://cs302.pythonanywhere.com/listUsers')
		serverUsersResponse = urllib2.urlopen(serverUsersRequest,timeout=5)
		serverUsersData = serverUsersResponse.read()
		serversUsersList = serverUsersData.split(',')
		
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		for UPI in serversUsersList:		
			c.execute("INSERT INTO ClientProfiles (profile_username,picture) SELECT ?,'https://upload.wikimedia.org/wikipedia/commons/thumb/4/42/Superman-facebook.svg/658px-Superman-facebook.svg.png' WHERE NOT EXISTS (SELECT * FROM ClientProfiles WHERE profile_username = ?)", (UPI,UPI))
		
		conn.commit() # commit actions to the database
		conn.close()
	
	def getClientProfile(self,profile_username=''):
		"""Returns the profile data corresponding to an input username"""
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		c.execute('''SELECT * FROM ClientProfiles WHERE profile_username = ?''', (profile_username,))
		profileData = c.fetchone()
		conn.close()
		
		return profileData
		
	def getUserData(self,username=''):
		"""Returns the user data corresponding to an input username"""
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		c.execute('''SELECT * FROM AllUsers WHERE username = ?''', (username,))
		userData = c.fetchone()
		conn.close()		
		return userData	
	
	@cherrypy.expose
	def updateClientProfileDetails(self,username=None, fullname=None, position=None, description=None, location=None, picture=None):
		"""Updates a row of the ClientProfiles tables which has a username value that corresponds to an input username value """
		
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		
		if not((fullname == "")or(fullname==None)):#As long as the input values are not empty, insert them into the database
			c.execute('''UPDATE ClientProfiles SET fullname = ? WHERE profile_username = ?''',(fullname, username))	
		if not((position == "")or(position==None)):
			c.execute('''UPDATE ClientProfiles SET position = ? WHERE profile_username = ?''',(position, username))	
		if not((description == "")or(description==None)):
			c.execute('''UPDATE ClientProfiles SET description = ? WHERE profile_username = ?''',(description, username))	
		if not((location == "")or(location==None)):
			c.execute('''UPDATE ClientProfiles SET location = ? WHERE profile_username = ?''',(location, username))	
		if not((picture == "")or(picture==None)):
			c.execute('''UPDATE ClientProfiles SET picture = ? WHERE profile_username = ?''',(picture, username))	
		
		conn.commit()
		conn.close()
		
		raise cherrypy.HTTPRedirect('/') #redirect back to the index
		
	
	def createMessagesTable():
		"""Creates a table to store all messages"""
		conn = sqlite3.connect(DB_USER_DATA)
		
		# Once we have a Connection, we can create a Cursor object and call its execute() method to perform SQL commands
		c = conn.cursor()
		
		c.execute('''CREATE TABLE IF NOT EXISTS Messages (id INTEGER PRIMARY KEY, sender TEXT, destination TEXT, message TEXT, stamp REAL, markdown TEXT, isFile TEXT, fileLink TEXT, fileType TEXT, fileName TEXT)''')
		
		conn.commit()
		conn.close()
	
	def getMessages(self,sender, destination):
		"""Returns all the messages stored in the database that correspond to the two input usernames"""
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		c.execute('''SELECT * FROM Messages WHERE ((sender=? AND destination=?)OR (sender=? AND destination=?)) order by stamp ''',(sender,destination,destination,sender))
		messages = c.fetchall()
		conn.commit()
		conn.close()		
		return messages
		
	def getMessagesForOneUser(self, destination=''):
		"""Returns all the messages stored in the database which have a destination that corresponds to the input username """
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		c.execute('''SELECT * FROM Messages WHERE ( destination=?) order by stamp ''',(destination))
		messages = c.fetchall()
		conn.commit()
		conn.close()		
		
		return messages	
		
	def insertIntoMessagesTable(self, sender = None, destination = None, message = None, stamp = None, markdown = '0',isFile = 'false', fileLink = None, fileType = None,fileName=None):	
		"""Inserts a message and its metadata in its own row in the Messages table as long as it doesn't already exist in the table """
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		
		c.execute('SELECT * FROM Messages WHERE (sender=? AND destination=? AND message=? AND stamp=?)', (sender, destination, message,stamp))
		data = c.fetchone()
		
		if data is None:#if input message is not in table, then insert it
			
			c.execute('INSERT INTO Messages (sender,destination,message,stamp,markdown,isFile,fileLink,fileType,fileName) VALUES (?,?,?,?,?,?,?,?,?)', (sender,destination,message,stamp,markdown,isFile,fileLink,fileType,fileName))
			
		conn.commit()
		conn.close()
		
	def createAllUsersTable():
		"""Creates a table to store all the users details/data"""
		conn = sqlite3.connect(DB_USER_DATA)		
		
		# Once we have a Connection, we can create a Cursor object and call its execute() method to perform SQL commands
		c = conn.cursor()
		
		c.execute('''CREATE TABLE IF NOT EXISTS AllUsers (id INTEGER PRIMARY KEY, username TEXT, ip TEXT, location TEXT, lastLogin TEXT, port TEXT, status TEXT, publicKey TEXT)''')
		
		conn.commit()
		conn.close()
		
	
	def populateAllUsersTable():
		"""Populates the AllUsers table with usernames from the login server's listUsers API"""
		serverUsersRequest = urllib2.Request('http://cs302.pythonanywhere.com/listUsers')
		serverUsersResponse = urllib2.urlopen(serverUsersRequest,timeout=10)
		serverUsersData = serverUsersResponse.read()
		serversUsersList = serverUsersData.split(',')
		
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		c.execute("UPDATE AllUsers SET status = 'Offline'")
		for UPI in serversUsersList:		
			c.execute("INSERT INTO AllUsers (username) SELECT ? WHERE NOT EXISTS (SELECT * FROM AllUsers WHERE username = ?)", (UPI,UPI))
		
		conn.commit() # commit actions to the database
		conn.close()
		

		
	def updateAllUsersTable(self, onlineUsersData, firstLogin = False):
		"""Updates the AllUsers table with new online user data"""
		onlineUsersData = json.loads(onlineUsersData)
		
		serverUsersRequest = urllib2.Request('http://cs302.pythonanywhere.com/listUsers')
		serverUsersResponse = urllib2.urlopen(serverUsersRequest,timeout=10)
		serverUsersData = serverUsersResponse.read()
		serversUsersList = serverUsersData.split(',')	#get list of users from server	
		
		print 'requesting status data from other online users'
		for value in onlineUsersData.itervalues():#loop through each user in the online user data 
			if(firstLogin == False):	
				try: #Do a getStatus request on each online user				
					userData = self.getUserData(value['username'])	
					ip = userData[2]
					port = userData[5]
					output_dict = {'profile_username':value['username']}
					data = json.dumps(output_dict) #data is a JSON object
					request = urllib2.Request('http://'+ ip + ':' + port + '/getStatus' , data, {'Content-Type':'application/json'})				
					response = urllib2.urlopen(request,timeout=1).read()				
					responseDict = json.loads(response)				
					status = str(responseDict['status'])
					if(status.lower()=='online')or(status.lower()=='offline')or(status.lower()=='away')or(status.lower()=='idle')or(status.lower()=='do not disturb'):
						pass
					else:
						status = 'Online'
					print ('requesting user status for '+value['username'])
				except:
					status = 'Online' #If a getStatus request on an online user fails or returns an invalid value, set that user's status in the database to 'Online'
			else:
				status = 'Online'
			
			conn = sqlite3.connect(DB_USER_DATA)
			c = conn.cursor()
			try:#update a row corresponding to a username
				c.execute('''UPDATE AllUsers SET ip = ? , location = ?, lastLogin = ?, port = ?, status = ? WHERE username = ?''', (value['ip'], value['location'], value['lastLogin'], value['port'], status, value['username']))
				if value['username'] in serversUsersList: 
					serversUsersList.remove(value['username'])
			except:
				pass
			
			try:
				c.execute('''UPDATE AllUsers SET publicKey = ? WHERE username = ?''',(value['publicKey'], value['username']))
			except:
				pass
			
			conn.commit() # commit actions to the database
			conn.close()	
		
		for user in serversUsersList: #Set the status of the remaining users in the database who are logged off to Offline
			conn = sqlite3.connect(DB_USER_DATA)
			c = conn.cursor()
			c.execute('''UPDATE AllUsers SET status = 'Offline' WHERE username = ?''',(user,))
			conn.commit() # commit actions to the database
			conn.close()
		
	def getAllUsersData(self):
		"""Returns every row in the AllUsers table"""
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		c.execute("SELECT * FROM AllUsers")
		usersData = c.fetchall()
		conn.commit()
		conn.close()
		return usersData
	

	
	#Initialise all the tables on startup
	createAllUsersTable()
	createMessagesTable()
	populateAllUsersTable()
	createClientProfilesTable()
	populateClientProfilesTable()
	createRequestRateTable()
	
	def __init__(self):
		"""Init function that sets up the Main User variables when this class is initialised"""
		cherrypy.engine.subscribe('stop',self.serverExitLogOff)#On server shutdown, automatically logs off current logged in user
		self.currentUser = None
		self.currentUserHashedPassword = None
	
	# If they try somewhere we don't know, catch it here and send them to the right place.
	@cherrypy.expose
	def default(self, *args, **kwargs):
		"""The default page, given when we don't recognise where the request is for."""
		Page = "I don't know where you're trying to go, so have a 404 Error."
		cherrypy.response.status = 404
		return Page

	# PAGES (which return HTML that can be viewed in browser)
	@cherrypy.expose
	def index(self):
		"""Redirects to the User list page or to the login page if there is no current user logged in"""		
		try:						
			username = cherrypy.session['username'] 
			raise cherrypy.HTTPRedirect('/openUsersListPage')
			
		except KeyError: #There is no username
		    raise cherrypy.HTTPRedirect('/login')		    
		return Page
	
	@cherrypy.expose
	def listAPI(self):
		"""Returns the APIs supported , as well as the encryption and hashing standards """
		
		return '/receiveMessage [sender] [destination] [message] [stamp] [markdown(opt)] [markdown(opt)] [encoding(opt)] [encryption(opt)] [hashing(opt)] [hash(opt)] [decryptionKey(opt)] Encoding <>  Encryption <>  Hashing <>'
        
	@cherrypy.expose
	def login(self):
		"""Opens the login.html page"""
		try:			
			Page = open('login.html').read().format(statusText = cherrypy.session['loginStatusText'])
		except:
			Page = open('login.html').read().format(statusText = 'Enter your Username and Password')	
		
		return Page
	
	@cherrypy.expose
	def openMessagingPage(self,destination=None):
		"""Opens the messaging.html page and inserts into it the messages between the logged in user and the destination user """
		try:			
			client = cherrypy.session['username']
			destinationUserData = self.getUserData(destination) #get user data for destination user
			messages = self.getMessages(client,destination)#retrieve all stored messages between these 2 users
			messages.reverse()#reverse this list so that the newest messages will appear at the top of the page
			if (not(destinationUserData[4]==None)):
				lastLogin = (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(destinationUserData[4]))))#convert epoch time to readable format
			else:
				lastLogin = ''
			destinationUserDetails = destination+'	'+'Last Login:'+lastLogin+' '+destinationUserData[6]
			
			userConversation = ''
			for message in messages:
				if (str(message[5])=='1'):
					userMessage = markdown.markdown(message[3])#if markdown flag is 1, then carry out this function
				else:
					userMessage = message[3]
				
				if((client==message[1])and(destination==message[2])):#message sent by client
					userConversation += ('<li class="i"> <div class="head"> <span class="time">'+(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(message[4]))))+'</span> <span class="name">You</span> </div> <div class="message">'+userMessage+'</div>  </li>')	
				elif((client==message[2])and(destination==message[1])):#message sent from destination
					userConversation += ('<li class="friend"> <div class="head"> <span class="name">'+destination+'</span> <span class="time">'+(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(message[4]))))+'</span> </div> <div class="message">'+userMessage+'</div> </li>')
			Page = open('messaging.html').read().format(receiverUsername = destination, senderUsername = client,userDetails = destinationUserDetails,userMessages=userConversation)
			return Page
		except:
			pass
		raise cherrypy.HTTPRedirect('/login') #redirect back to login page
		
	@cherrypy.expose
	def openUsersListPage(self):
		"""Opens the usersPage.html page and inserts into it the list of users on the server and their online status """
		try:
			
			client = cherrypy.session['username']	
			usersData = self.getAllUsersData() 
			userDetails = ''
			for user in usersData:
				
				userDetails += ('''<div class="user"><button type="submit" class="msgBtn2" onclick="window.location.href='/openMessagingPage?destination='''+user[1]+''''">'''+user[1]+'''---'''+user[6]+'''</button><button type=submit class="msgBtn3" onclick="window.location.href='/viewProfilePage?username='''+user[1]+''''">View Profile</button></div>''')	
			Page = open('usersPage.html').read().format(userList = userDetails,username=client,userstatus=cherrypy.session['userStatus'])
			return Page
		except:	
			raise cherrypy.HTTPRedirect('/login') #redirect back to login page
	
	@cherrypy.expose
	def viewProfilePage(self,username=None):
		"""Opens the viewProfile.html page and inserts into it the profile data that corresponds to the input username """
		try:			
			client = cherrypy.session['username']
		except:
			raise cherrypy.HTTPRedirect('/login')#if no client is logged in then redirect back to the login page
		
		try:
			if username == None:				
				username = client
			if (client == username): #The current logged in user requesting to see their own profile page, so no need to do an external getProfile request
				clientData = self.getClientProfile(client)
				
				Page = open('viewProfile.html').read().format(profileHeading = 'MY',UPI = client,fullname=clientData[2],position=clientData[3],description=clientData[4],location=clientData[5],image=clientData[6])
				return Page
			else:
				userData = self.getUserData(username) #get user data of the profile to display
				
				ip = userData[2]
				port = userData[5]				
				
				output_dict = {'sender':client,'profile_username':username}
				
				data = json.dumps(output_dict) #data is a JSON object
				
				request = urllib2.Request('http://'+ ip + ':' + port + '/getProfile' , data, {'Content-Type':'application/json'}) #Do a getProfile request to the user
				
				response = urllib2.urlopen(request,timeout=5).read()
				
				responseDict = (json.loads(response))
				
				Page = open('viewProfile.html').read().format(profileHeading = 'USER',UPI = username,fullname=responseDict['fullname'],position=responseDict['position'],description=responseDict['description'],location=responseDict['location'],image=responseDict['picture'])
				return Page
		except:
			
			Page = open('viewProfile.html').read().format(profileHeading = 'No data available for USER',UPI = username,fullname='',position='',description='',location='',image='')
			return Page
			
		
	@cherrypy.expose
	def editProfile(self):
		"""Opens the editProfile.html page """
		try:			
			Page = open('editProfile.html').read().format(clientUsername=cherrypy.session['username'])	
			return Page
		except:
			raise cherrypy.HTTPRedirect('/openUsersListPage')	#if no user is logged in redirect back to the login page		
    
	@cherrypy.expose
	def ping(self, sender=None):
		"""Allows another client to check if this client is still here before initiating other communication. """
		try:
			if(self.checkIfRateLimited(sender)):#Check for rate limiting
				return '11: Blacklisted or Rate Limited'
		except:
			pass
		if (sender ==None):
			return '1: Missing Compulsory Field'
		else:	
			return '0'
	
	@cherrypy.expose
	@cherrypy.tools.json_in()
	def getProfile(self):
		"""This API allows another client to request information about the user operating this client """
		try:			
			input = cherrypy.request.json
			if((not('sender' in input))or(not('profile_username' in input))):
				return '1: Missing Compulsory Field'
			if(self.checkIfRateLimited(input['sender'])):#Check for rate limiting
				return '11: Blacklisted or Rate Limited'	
			profileData = self.getClientProfile(input['profile_username'])#get profile data from database
			outputDict = {'fullname':profileData[2],'position':profileData[3],'description':profileData[4], 'location':profileData[5], 'picture':profileData[6], 'encoding':profileData[7], 'encryption':profileData[8], 'decryptionKey': profileData[9]}
			return json.dumps(outputDict) #data is a JSON object
		except:
			return 'Error: Something Went Wrong'	

	
	@cherrypy.expose
	@cherrypy.tools.json_in()
	def receiveFile(self):
		"""This API allows another client to send this client an arbitrary file (in binary) """
		try:			
			input_data = cherrypy.request.json
			
			if(not('sender' in input_data))or(not('destination' in input_data))or(not('file' in input_data))or(not('stamp' in input_data)or(not('filename' in input_data))or(not('content_type' in input_data))):
				return '1: Missing Compulsory Field' 
			
			if(self.checkIfRateLimited(input_data['sender'])):#Check for rate limiting
				return '11: Blacklisted or Rate Limited'
			
			if('encryption' in input_data):
				if (input_data['encryption'] == None):
					pass
				elif (not(str(input_data['encryption']) == '0')):
					return '9: Encryption Standard Not Supported' 
			print ('file sent from: '+input_data['sender'])
			base64Length = len(input_data['file'])
			fileLength = base64Length * 0.75
			
			if (fileLength>5242880):#Check to see if file is less than 5MB
				return ('4: File exceeds 5MB')
						
			inputFile = (input_data['file']).decode('base64')
			
			fileName = input_data['filename']
						
			#Depending on the content_type of the file, an html line of code will be stored in the database so that file can be viewed in an embedded form in the messages page 
			if 'image/' in input_data['content_type']:
				fileMessage = '<img src="receivedFiles/'+fileName+'" alt= Picture 380x320 height="320" width="380">'#embedded image	
			elif 'video/' in input_data['content_type']:
				fileMessage = '<video width="380" height="320" controls><source src="'+'receivedFiles/'+fileName+'">Your browser does not support the video tag.</video>'#embedded video player
			elif 'audio/' in input_data['content_type']:
				fileMessage = '<audio controls> <source src="'+'receivedFiles/'+fileName+'">Your browser does not support the audio element.</audio>'#embedded audio player
			else:
				fileMessage = '<a href="receivedFiles/'+fileName+'" download>'+fileName +'</a>'#download link for file
						
			self.insertIntoMessagesTable(input_data['sender'], input_data['destination'], fileMessage, input_data['stamp'], '0','true', fileName,input_data['content_type'])
			
			#save the file in the receiveFiles folder
			outFile = open('public/receivedFiles/'+fileName,'wb')
			outFile.write(inputFile)
			outFile.close
			print (fileName+' has been received')
			return ('0: Success')
		except:
			return ('Error: Something went wrong')
		
	@cherrypy.expose
	def sendFile(self, sender=None, destination=None, outFile=None,stamp = None,encryption=0, hashing = 0, hashedFile = None, decryptionKey=None):
		"""Allows the client to send another user a file and its metadata"""
		try:	
			if(self.checkIfRateLimited(sender)): #Check for rate limiting
				return '11: Blacklisted or Rate Limited'
			destinationUserData = self.getUserData(destination)
			ip = destinationUserData[2]
			port = destinationUserData[5]
			if (stamp == None)or(stamp== ''):#if no stamp value is provided, generate one
				stamp = float(time.time())
						
			fileName = outFile.filename
			content_type = outFile.content_type.value
			print (fileName + ' is preparing to be sent') 
			
			encoded = base64.b64encode(outFile.file.read())#encode file to base64
			
			output_dict = {'sender':sender,'destination':destination,'file':encoded, 'stamp':stamp, 'filename':fileName,'content_type':content_type, 'encryption':encryption, 'hashing':hashing, 'hash': hashedFile}#, 'decryptionKey':decryptionKey}
			data = json.dumps(output_dict) #data is a JSON object
			request = urllib2.Request('http://'+ ip + ':' + port + '/receiveFile' , data, {'Content-Type':'application/json'})
			sendResponse = '  '
			fileSentOffline = False
			try:			
				response = urllib2.urlopen(request,timeout=5)
				sendResponse = response.read()
				print ('file send response: '+sendResponse)
			except:
				#if the user is offline, send the file to other online users
				thread.start_new_thread(self.sendOfflineFile, (data, cherrypy.session['username'], cherrypy.session['hashedPassword']))
				fileSentOffline = True
				
			#Depending on the content_type of the file, an html line of code will be stored in the database so that file can be viewed in an embedded form in the messages page 	
			if 'image/' in output_dict['content_type']:
				fileMessage = '<img src="receivedFiles/'+fileName+'" alt= Picture 380x320 height="320" width="380">'#embedded image	
			elif 'video/' in output_dict['content_type']:
				fileMessage = '<video width="380" height="320" controls><source src="'+'receivedFiles/'+fileName+'">Your browser does not support the video tag.</video>'#embedded video
			elif 'audio/' in output_dict['content_type']:
				fileMessage = '<audio controls> <source src="'+'receivedFiles/'+fileName+'">Your browser does not support the audio element.</audio>'#embedded audio
			else:
				fileMessage = '<a href="receivedFiles/'+fileName+'" download>'+fileName +'</a>'#embedded download link
			
			
			
			if (str(sendResponse[0]) == '0')or(str(sendResponse[1]) == '0')or(fileSentOffline == True):
				#save the file in the receivedFiles folder
				saveFile = open('public/receivedFiles/'+fileName,'wb')
				saveFile.write((output_dict['file']).decode('base64'))
				saveFile.close
				self.insertIntoMessagesTable(output_dict['sender'], output_dict['destination'], fileMessage, output_dict['stamp'], '0','true', fileName, content_type)
			else:	
				print 'file send confirmation not received'
		except:
			print 'file send error'
			if(sender==None)or(destination==None):
				raise cherrypy.HTTPRedirect('/login')
		raise cherrypy.HTTPRedirect('/openMessagingPage?destination='+destination)	
		#redirect back to destination user page
	
	        
	# LOGGING IN AND OUT
	@cherrypy.expose
	def signin(self, username=None, password=None):
		"""Check their name and password and send them either to the main page, or back to the 	main login screen."""
		try:	
			if(self.checkIfRateLimited(username)):#check for rate limiting
				return '11: Blacklisted or Rate Limited'
		except:
			pass
		
		hashOfPasswordPlusSalt = None
		if(not(password==None)):
			passwordPlusSalt = password + SALT
			hashOfPasswordPlusSalt = hashlib.sha256(passwordPlusSalt).hexdigest()
		error = self.authoriseUserLogin(username,hashOfPasswordPlusSalt, True)
		if (error == 0):#check if login is successful
			cherrypy.session['username'] = username;
			cherrypy.session['hashedPassword'] = hashOfPasswordPlusSalt;#storing hashed password is more secure than storing plain password
			cherrypy.session['userStatus'] = 'Online'
			self.currentUser = cherrypy.session['username']
			self.currentUserHashedPassword = cherrypy.session['hashedPassword']
						
			self.serverReportThreading(cherrypy.session['username'],cherrypy.session['hashedPassword'])#start new thread that will be used to continously log the client back into the login server
			raise cherrypy.HTTPRedirect('/openUsersListPage')
		else:
			cherrypy.session['loginStatusText'] = "Username or Password is Incorrect"
			raise cherrypy.HTTPRedirect('/login')
		
			

	@cherrypy.expose
	def signout(self,serverShutDown = False):
		"""Logs the current user out, expires their session"""
		
		redirectToLoginPage = False
		username = None
		try:			
			try:
				username = cherrypy.session['username']
				hashedPassword = cherrypy.session['hashedPassword']
			except:
				username = self.currentUser
				hashedPassword = self.currentUserHashedPassword
			if (username == None):
				pass
			else:					
				logoutRequest = urllib2.Request('https://cs302.pythonanywhere.com/logoff?username=' + username + '&password=' + hashedPassword + '&enc=0')
				logoutResponse = urllib2.urlopen(logoutRequest)	
				logoutData = logoutResponse.read()
				print ('Server Logout Report: '+logoutData)
				if(serverShutDown == True):
					return
				
				
				cherrypy.lib.sessions.expire()	#expire session data		
			redirectToLoginPage = True			
		except:			
			try:
				cherrypy.lib.sessions.expire()
			except:
				pass
			redirectToLoginPage = True
			
		if(serverShutDown == True):#if this function is called because of server shutdown, then no need to redirect back to the login page
			return			
		if(redirectToLoginPage):
			raise cherrypy.HTTPRedirect('/login')
		
	def serverExitLogOff(self):
		"""This function is called when the server shuts down, this function then calls the signout function to log out the current user (if any) """
		print('Server Exit Procedure Initiated')
		self.signout(True)	
        
	def serverReportThreading(self,username,hashedPassword):
		"""This function starts a new thread that runs the serverReportTimer function, which is used to communicate with the login server regularly"""
		thread.start_new_thread(self.serverReportTimer, (username,hashedPassword))
		
		
	def serverReportTimer(self,username,hashedPassword):
		"""This function first calls the requestOfflineMessages function to retrieve any messages that this client may have received when they were online
		and then after that, every 30 seconds logs the current client back into the login server and also resets the RateRequest table"""
		beginTime=time.time()
		loop = True
		try:
			self.requestOfflineMessages(username,hashedPassword)#request messages that client received while offline
		except:
			print 'offline msg request failed'
		while (loop == True):
			
			if(self.checkIfStillLoggedIn(username,hashedPassword)):	#if the user has been logged out, don't try logging them in again and kill the thread
				try:
					self.clearRateRequestTable()#clear request number values back to 0
					self.authoriseUserLogin(username,hashedPassword)#log the user in periodically
				except:
					pass	
				time.sleep(30.0-((time.time()-beginTime)%30.0))#how many secs there are to the nearest 30 sec block of time, 30 minus that to figure out how long you have to sleep, the reason I do this is to account for variable execution times for self.authoriseUserLogin()
			else:			
				loop = False
		print 'server login report thread exited'
		thread.exit()		
	
	def checkIfStillLoggedIn(self, username=None, hashedPassword=None):
		"""Calls the login server's getList method to determine whether the input username is still logged in"""
		try:
			ip = self.getIP()
			location = self.getLocation(ip)
			onlineUsersRequest = urllib2.Request('http://cs302.pythonanywhere.com/getList?username='+username+'&password='+hashedPassword+'&enc=0&json=1')
			onlineUsersResponse = urllib2.urlopen(onlineUsersRequest)
			onlineUsersData = onlineUsersResponse.read()
			onlineUsersData = json.loads(onlineUsersData)
			
			for value in onlineUsersData.itervalues():				
				if(value['username']==username):
					return True			
		except:
			pass
		return False
	
	def authoriseUserLogin(self, username=None, hashedPassword=None, firstLogin = False):
		"""Logs a client into the login server with the input credentials also updates the AllUsers table with new online user data from the login server"""
		try:
			ip = self.getIP()
			location = self.getLocation(ip)
			if ((username==None)or(username=='')or(hashedPassword==None)or(hashedPassword=='')):
				return 1	
				
			loginRequest = urllib2.Request('http://cs302.pythonanywhere.com/report?username='+username+'&password='+hashedPassword+'&location='+location+'&ip='+ip+'&port='+str(listen_port)+'&enc=0')	#Object which represents the HTTP request we are making
			
			loginResponse = urllib2.urlopen(loginRequest,timeout=10)#Returns a response object for the requested URL
			loginData = loginResponse.read() #The response is a file-like object, so .read() can be called on it
			
			
			print ('Server login report: '+loginData)
			
			
			if(loginData[0]=='0'):#if login is successful, request online user data
				onlineUsersRequest = urllib2.Request('http://cs302.pythonanywhere.com/getList?username='+username+'&password='+hashedPassword+'&enc=0&json=1')
				onlineUsersResponse = urllib2.urlopen(onlineUsersRequest,timeout=5)
				onlineUsersData = onlineUsersResponse.read()
				
				self.updateAllUsersTable(onlineUsersData, firstLogin)
				
			
			
			if (loginData[0] == "0") :
				return 0
			else:
				return 1
		except:
			print 'Login Report To Server Failed'
			return 1
				
	@cherrypy.expose
	@cherrypy.tools.json_in()	
	def retrieveMessages(self):
		"""This API allows a requesting client that has recently logged on to ask this client for any messages that were intended for the requesting client when they were offline"""
		try:			
				
			input = cherrypy.request.json
			if(not('requestor' in input)):
				return '1: Missing Compulsory Field'
			elif((input['requestor'])==None)or((input['requestor'])==''):	
				return '1: Missing Compulsory Field'
			requestor = input['requestor']	
			
			if(self.checkIfRateLimited(input['requestor'])):#check for rate limiting
				return '11: Blacklisted or Rate Limited'
			
			messagesForRequestor = self.getMessagesForOneUser(requestor)
			for message in messagesForRequestor:
				
				stamp = message[4]
				if (message[6]=='false'):#send message
					self.sendMessage(message[1], message[2], message[3],message[5],float(stamp))
				elif (message[6]=='true'):
					fileName = message[7]
								
			return '0: Success'
		except:
			return 'Error: Something Went Wrong'	
	
	@cherrypy.expose
	def openSetUserStatusPage(self):
		"""Opens the editUserStatus.html page"""
		try:
			
			
			username = cherrypy.session['username']
			Page = open('editUserStatus.html')
			return Page
		except:
			pass
		raise cherrypy.HTTPRedirect('/openUsersListPage')
	
	@cherrypy.expose
	def setUserStatus(self,userStatus = 'Online'):
		"""Updates the status of the current logged in user with the input value """
		try:				
			cherrypy.session['userStatus'] = userStatus			
			conn = sqlite3.connect(DB_USER_DATA)			
			c = conn.cursor()			
			c.execute('''UPDATE AllUsers SET status = ? WHERE username = ?''',(userStatus, cherrypy.session['username']))			
			conn.commit() # commit actions to the database			
			conn.close()			
		except:			
			print 'error setting user status'
		raise cherrypy.HTTPRedirect('/openUsersListPage')

		
	
	@cherrypy.expose
	@cherrypy.tools.json_in()
	def getStatus(self):
		"""This API allows another client to request information about the current status of the user operating this client. The valid values to be returned are {Online, Idle, Away, Do Not Disturb, Offline}."""
		try:						
			input = cherrypy.request.json
			if(not('profile_username' in input)):				
				return '1: Missing Compulsory Field'
			userStatus = self.getUserData(input['profile_username'])#get user status from database
			
			outputDict = {'status':userStatus[6]}
			return json.dumps(outputDict)
		except:
			return '3: Client Currently Unavailable'
	
	@cherrypy.expose
	def requestOfflineMessages(self,username,hashedPassword):
		"""Calls the retrieveMessages API of all logged in users to get any messages this client may have received while they were offline"""
		try:
			if(self.checkIfRateLimited(username)):	#check for rate limiting
				return '11: Blacklisted or Rate Limited'
			
			
			onlineUsersRequest = urllib2.Request('http://cs302.pythonanywhere.com/getList?username='+username+'&password='+hashedPassword+'&enc=0&json=1')
			onlineUsersResponse = urllib2.urlopen(onlineUsersRequest,timeout=5)
			onlineUsersData = onlineUsersResponse.read()
			onlineUsersData = json.loads(onlineUsersData)
			
			output_dict = {'requestor':username}
			data = json.dumps(output_dict) #data is a JSON object
			
			for value in onlineUsersData.itervalues():#loop through all online users
				try:
					userToRequest = value['username']
					if (not(userToRequest == username)):
						destinationUserData = self.getUserData(userToRequest)
						ip = destinationUserData[2]
						port = destinationUserData[5]
						#call retrieveMessages API on all online users
						request = urllib2.Request('http://'+ ip + ':' + port + '/retrieveMessages', data, {'Content-Type':'application/json'})
						response = urllib2.urlopen(request,timeout=1)
						print('offline messages request response: '+response.read())							
				except:
					pass			
		except:
			print('Error trying to retrieve Offline Messages')
		
	
	@cherrypy.expose
	@cherrypy.tools.json_in()
	def receiveMessage(self):
		"""This API allows another client to send this client a message"""
		try:			
			input_data = cherrypy.request.json			
			
			if(not('sender' in input_data))or(not('destination' in input_data))or(not('message' in input_data))or(not('stamp' in input_data)):
				return '1: Missing Compulsory Field' 
			
			if(self.checkIfRateLimited(input_data['sender'])):#Check for rate limiting
				return '11: Blacklisted or Rate Limited'
			
			if('encryption' in input_data):
				if (input_data['encryption'] == None):
					pass
				elif (not(str(input_data['encryption']) == '0')):
					
					return '9: Encryption Standard Not Supported' 
			
			markDown='0'
			if ('markdown' in input_data):
				if (input_data['markdown'] == None):
					message = input_data['message'] 
				elif ((str(input_data['markdown'])) == '1'):
					
					message = markdown.markdown(input_data['message'])
					markDown = '1'
					
				else:
					
					message = input_data['message'] 
			else:
				
				message = input_data['message'] 
			
			self.insertIntoMessagesTable(input_data['sender'], input_data['destination'], message, input_data['stamp'], markDown,'false', None,None)
			return ('0: Success')
		except Exception as e: 
			print e
			return ('Error: Something went wrong')
		
	@cherrypy.expose
	def sendMessage(self, sender=None, destination=None, message='Default Message',markDown='0',stamp=None,encryption=0, hashing = 0, hashedMessage = None, decryptionKey=None):	
		"""This function allows the logged in client to send a message and its metadata to another user"""
		
		try:	
			if(self.checkIfRateLimited(sender)): #Check for rate limiting
				return '11: Blacklisted or Rate Limited'
			
			if ((message == None)or(message == '')): #if the message field is empty redirect back to the messaging page
				raise cherrypy.HTTPRedirect('/openMessagingPage?destination='+destination)
			destinationUserData = self.getUserData(destination)
			
			ip = destinationUserData[2]
			port = destinationUserData[5]
			
			if (stamp == None)or(stamp== ''):#generate stamp if it doesn't already exist
				stamp = float(time.time())
			output_dict = {'sender':sender,'destination':destination,'message':message, 'stamp':stamp, 'markdown':int(markDown), 'encryption':encryption, 'hashing':hashing, 'hash': hashedMessage, 'decryptionKey':decryptionKey}
			data = json.dumps(output_dict) #data is a JSON object
			
			request = urllib2.Request('http://'+ ip + ':' + port + '/receiveMessage', data, {'Content-Type':'application/json'})
			try:
				response = urllib2.urlopen(request,timeout=5)
				print response.read()
			except:
				#send message offline if the destination user is offline
				message = 'Msg Sent Offline: ' + message
				output_dict = {'sender':sender,'destination':destination,'message':message, 'stamp':stamp, 'markdown':int(markDown), 'encryption':encryption, 'hashing':hashing, 'hash': hashedMessage, 'decryptionKey':decryptionKey}
				data = json.dumps(output_dict) #data is a JSON object
				#call sendOfflineMessage function on its own thread, so that the rest of the program doesn't have to wait on it.
				thread.start_new_thread(self.sendOfflineMessage, (data, cherrypy.session['username'], cherrypy.session['hashedPassword']))
			
			if (str(markDown)=='1'):
				message = markdown.markdown(output_dict['message'])
			
			#save message in database
			self.insertIntoMessagesTable(output_dict['sender'], output_dict['destination'], message, output_dict['stamp'], int(markDown),'false', None,None)
			
		except : 			
			print 'send message error'
			if(sender==None)or(destination==None):
				raise cherrypy.HTTPRedirect('/login')
		#redirect back to messaging page
		raise cherrypy.HTTPRedirect('/openMessagingPage?destination='+destination)	
	
	def sendOfflineMessage(self,data,username,hashedPassword):
		"""This function sends a message that is meant for an offline user, to every currently online user """
		try:	
			print 'Sending Message Offline'
			
			onlineUsersRequest = urllib2.Request('http://cs302.pythonanywhere.com/getList?username='+username+'&password='+hashedPassword+'&enc=0&json=1')
			onlineUsersResponse = urllib2.urlopen(onlineUsersRequest,timeout=5)
			onlineUsersRead = onlineUsersResponse.read()
			onlineUsersData = json.loads(onlineUsersRead) #get online user data
						
			for value in onlineUsersData.itervalues():	#send message to all online	users			
				try:					
					ip = value['ip']
					port = value['port']
					
					request = urllib2.Request('http://'+ ip + ':' + port + '/receiveMessage' , data, {'Content-Type':'application/json'})				
					response = urllib2.urlopen(request,timeout=2).read()				
					
				except:
					pass
			print 'Offline Message sent successfully'	
		except:
			pass			
		thread.exit()	
		
	def sendOfflineFile(self,data,username,hashedPassword):
		"""This function sends a file that is meant for an offline user, to every currently online user """
		try:	
			print 'Sending File Offline'
			
			onlineUsersRequest = urllib2.Request('http://cs302.pythonanywhere.com/getList?username='+username+'&password='+hashedPassword+'&enc=0&json=1')
			onlineUsersResponse = urllib2.urlopen(onlineUsersRequest,timeout=5)
			onlineUsersRead = onlineUsersResponse.read()
			onlineUsersData = json.loads(onlineUsersRead)			
			
			for value in onlineUsersData.itervalues(): #send file to all online users					
				try:					
					ip = value['ip']
					port = value['port']
					
					request = urllib2.Request('http://'+ ip + ':' + port + '/receiveFile' , data, {'Content-Type':'application/json'})				
					response = urllib2.urlopen(request,timeout=2).read()				
					
				except:
					pass
			print 'Offline File sent successfully'	
		except:
			pass			
		thread.exit()		
	 

	cherrypy.config.update({'error_page.404': default,'server.socket_host': '127.0.0.1','server.socket_port': 10001,'engine.autoreload.on': True,'tools.sessions.on': True,'tools.encode.on': True,'tools.encode.encoding': 'utf-8','tools.staticdir.on' : True,	'tools.staticdir.dir' : os.path.join(os.getcwd(), 'public'),'tools.staticdir.index' : 'login.html'})
	
	
	
def runMainApp():
	
	
    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. 
	cherrypy.tree.mount(MainApp(), "/")

	# Tell Cherrypy to listen for connections on the configured address and port.
	cherrypy.config.update({'server.socket_host': listen_ip,
		                    'server.socket_port': listen_port,
		                    'engine.autoreload.on': True,
		                   })

	print "========================="
	print "University of Auckland"
	print "COMPSYS302 - Software Design Application"
	print "========================================"                       
	
	# Start the web server
	cherrypy.engine.start()
	
	# And stop doing anything else. Let the web server take over.
	cherrypy.engine.block()
 
#Run the function to start everything
runMainApp()
