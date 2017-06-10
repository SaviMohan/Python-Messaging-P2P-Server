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
DB_USER_DATA = "relationalDatabase.db"


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
		if (('130.216.' in ip)or('10.103.' in ip)or('10.104.' in ip)):#####################################################################################
			return '0'	#Uni Desktop
		elif(('172.23.' in ip)or('172.24.' in ip)):
			return '1'	#Uni WiFi
		else:
			return '2'	#Rest of World
	
	def getIP(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.connect(("8.8.8.8",80))
		internalIP = s.getsockname()[0]
		s.close()
			
		externalIP = (urllib2.urlopen(urllib2.Request('http://ident.me'))).read().decode('utf8') #retrieves external ip	#encrypt?
		#print internalIP
		#print externalIP
		location = self.getLocation(internalIP)
		
		if((location == '0')or(location == '1')):
			
			return str(internalIP)
		else:
			return str(externalIP)
	
	def clearRateRequestTable(self):
		conn = sqlite3.connect(DB_USER_DATA)		
		# Once we have a Connection, we can create a Cursor object and call its execute() method to perform SQL commands
		c = conn.cursor()
		
		c.execute("UPDATE RequestRate SET requestsNumber = 0")
		
		conn.commit()
		conn.close()
		
	
	def checkIfRateLimited(self,requestor=None,IP= None):
		rateLimited = False
		conn = sqlite3.connect(DB_USER_DATA)			
		# Once we have a Connection, we can create a Cursor object and call its execute() method to perform SQL commands
		c = conn.cursor()
		c.execute('SELECT * FROM RequestRate WHERE (requestor=? )', (requestor,))
		data = c.fetchone()

		
		if data is None:			
			c.execute('INSERT INTO RequestRate (requestor,requestsNumber) VALUES (?,?)', (requestor,1))
		else:
			c.execute('''UPDATE RequestRate SET requestsNumber = ? WHERE requestor = ?''',(data[2]+1, requestor))	
			if(data[2]>8):
				rateLimited = True
		
		
		
		c.execute('SELECT * FROM RequestRate WHERE (requestor=? )', (IP,))
		IPdata = c.fetchone()

		
		if IPdata is None:			
			c.execute('INSERT INTO RequestRate (requestor,requestsNumber) VALUES (?,?)', (IP,1))
		else:
			c.execute('''UPDATE RequestRate SET requestsNumber = ? WHERE requestor = ?''',(IPdata[2]+1, IP))	
			if(IPdata[2]>8):
				rateLimited = True
		conn.commit()
		conn.close()

		return rateLimited	
		
		
		
	def createRequestRateTable():
		conn = sqlite3.connect(DB_USER_DATA)		
		
		# Once we have a Connection, we can create a Cursor object and call its execute() method to perform SQL commands
		c = conn.cursor()
		
		c.execute('''CREATE TABLE IF NOT EXISTS RequestRate (id INTEGER PRIMARY KEY, requestor TEXT, requestsNumber INTEGER)''')
		
		conn.commit()
		conn.close()	
	
	def createClientProfilesTable():
		conn = sqlite3.connect(DB_USER_DATA)
		
		
		
		# Once we have a Connection, we can create a Cursor object and call its execute() method to perform SQL commands
		c = conn.cursor()
		
		c.execute('''CREATE TABLE IF NOT EXISTS ClientProfiles (id INTEGER PRIMARY KEY, profile_username TEXT, fullname TEXT, position TEXT, description TEXT, location TEXT, picture TEXT, encoding TEXT, encryption TEXT, decryptionKey TEXT)''')
		
		conn.commit()
		conn.close()
	
	def populateClientProfilesTable():
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
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		c.execute('''SELECT * FROM ClientProfiles WHERE profile_username = ?''', (profile_username,))
		profileData = c.fetchone()
		conn.close()
		
		return profileData
		
	def getUserData(self,username=''):
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		c.execute('''SELECT * FROM AllUsers WHERE username = ?''', (username,))
		userData = c.fetchone()
		conn.close()
		#print 'test'
		#print userData
		#print 'test'
		return userData	
	
	@cherrypy.expose######################
	def updateClientProfileDetails(self,username=None, fullname=None, position=None, description=None, location=None, picture=None):
		""" """
		
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		
		if not((fullname == "")or(fullname==None)):
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
		
		raise cherrypy.HTTPRedirect('/')
		
	
	def createMessagesTable():
		conn = sqlite3.connect(DB_USER_DATA)
		
		# Once we have a Connection, we can create a Cursor object and call its execute() method to perform SQL commands
		c = conn.cursor()
		
		c.execute('''CREATE TABLE IF NOT EXISTS Messages (id INTEGER PRIMARY KEY, sender TEXT, destination TEXT, message TEXT, stamp REAL, markdown TEXT, isFile TEXT, fileLink TEXT, fileType TEXT, fileName TEXT)''')
		
		conn.commit()
		conn.close()
	
	def getMessages(self,sender, destination):
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		c.execute('''SELECT * FROM Messages WHERE ((sender=? AND destination=?)OR (sender=? AND destination=?)) order by stamp ''',(sender,destination,destination,sender))
		messages = c.fetchall()
		conn.commit()
		conn.close()
		
		#for message in messages:
			
			#print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(message[4]))))
		return messages
		
	def getMessagesForOneUser(self, destination=''):
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		c.execute('''SELECT * FROM Messages WHERE ( destination=?) order by stamp ''',(destination))
		messages = c.fetchall()
		conn.commit()
		conn.close()
		
		#for message in messages:
			
			#print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(message[4]))))
		return messages	
		
	def insertIntoMessagesTable(self, sender = None, destination = None, message = None, stamp = None, markdown = '0',isFile = 'false', fileLink = None, fileType = None,fileName=None):	
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		
		c.execute('SELECT * FROM Messages WHERE (sender=? AND destination=? AND message=? AND stamp=?)', (sender, destination, message,stamp))
		data = c.fetchone()

		
		if data is None:
			print 'testdb'
			c.execute('INSERT INTO Messages (sender,destination,message,stamp,markdown,isFile,fileLink,fileType,fileName) VALUES (?,?,?,?,?,?,?,?,?)', (sender,destination,message,stamp,markdown,isFile,fileLink,fileType,fileName))
			
		
		conn.commit()
		conn.close()
		
	def createAllUsersTable():
		conn = sqlite3.connect(DB_USER_DATA)
		
		
		
		# Once we have a Connection, we can create a Cursor object and call its execute() method to perform SQL commands
		c = conn.cursor()
		
		c.execute('''CREATE TABLE IF NOT EXISTS AllUsers (id INTEGER PRIMARY KEY, username TEXT, ip TEXT, location TEXT, lastLogin TEXT, port TEXT, status TEXT, publicKey TEXT)''')
		
		conn.commit()
		conn.close()
		
	
	def populateAllUsersTable():
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
		

		
	def updateAllUsersTable(self, onlineUsersData):
		onlineUsersData = json.loads(onlineUsersData)
		
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		#c.execute("UPDATE AllUsers SET status = 'Logged Off'")
		for value in onlineUsersData.itervalues():
			try:				
				userData = self.getUserData(value['username'])	#############################
				ip = userData[2]
				port = userData[5]
				output_dict = {'profile_username':value['username']}
				data = json.dumps(output_dict) #data is a JSON object
				request = urllib2.Request('http://'+ ip + ':' + port + '/getStatus' , data, {'Content-Type':'application/json'})				
				response = urllib2.urlopen(request,timeout=1).read()				
				responseDict = json.loads(response)				
				status = str(responseDict['status'])				
				print ('requesting user status for '+value['username'])
			except:
				status = 'Online'
				
			
				
				
			
			
			
			c.execute('''UPDATE AllUsers SET ip = ? , location = ?, lastLogin = ?, port = ?, status = ? WHERE username = ?''', (value['ip'], value['location'], value['lastLogin'], value['port'], status, value['username']))
			try:
				c.execute('''UPDATE AllUsers SET publicKey = ? WHERE username = ?''',(value['publicKey'], value['username']))
			except:
				pass
		conn.commit() # commit actions to the database
		conn.close()
		
	def getAllUsersData(self):
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		c.execute("SELECT * FROM AllUsers")
		usersData = c.fetchall()
		conn.commit()
		conn.close()
		return usersData
	

	
	
	createAllUsersTable()
	createMessagesTable()
	populateAllUsersTable()
	createClientProfilesTable()
	populateClientProfilesTable()
	createRequestRateTable()
	
	def __init__(self):
		cherrypy.engine.subscribe('stop',self.serverExitLogOff)
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
		#Page = "Welcome! This is a test website for COMPSYS302!<br/>"
		
		try:
			if(self.checkIfRateLimited(None,cherrypy.request.remote.ip)):
				return '11: Blacklisted or Rate Limited'
				
			username = cherrypy.session['username'] 
			raise cherrypy.HTTPRedirect('/openUsersListPage')
			#Page += "Hello " + cherrypy.session['username'] + "!<br/>"
			#Page += "Here is some bonus text because you've logged in!"
			
			#Page += "Click here to <a href='editProfile'>Edit Profile</a>."
			
			#Page += '<form action="/openMessagingPage?destination=abha808" method="post" enctype="multipart/form-data">'
			#Page += '<input type="submit" value="List of online users"/></form>'
		except KeyError: #There is no username
		    raise cherrypy.HTTPRedirect('/login')
		    #Page += "Click here to <a href='login'>login</a>."
		return Page
	
	@cherrypy.expose
	def listAPI(self):
		if(self.checkIfRateLimited(username,cherrypy.request.remote.ip)):
			return '11: Blacklisted or Rate Limited'		
		return '/receiveMessage [sender] [destination] [message] [stamp] [markdown(opt)] [markdown(opt)] [encoding(opt)] [encryption(opt)] [hashing(opt)] [hash(opt)] [decryptionKey(opt)] Encoding <>  Encryption <>  Hashing <>'
        
	@cherrypy.expose
	def login(self):
		try:
			if(self.checkIfRateLimited(None,cherrypy.request.remote.ip)):
				return '11: Blacklisted or Rate Limited'
			
			Page = open('login.html').read().format(statusText = cherrypy.session['loginStatusText'])
		except:
			Page = open('login.html').read().format(statusText = 'Enter your Username and Password')	
		#Page = open('usersPage.html')
		return Page
	
	@cherrypy.expose
	def openMessagingPage(self,destination=None):
		try:
			if(self.checkIfRateLimited(None,cherrypy.request.remote.ip)):
				return '11: Blacklisted or Rate Limited'
			
			client = cherrypy.session['username']
			destinationUserData = self.getUserData(destination)
			messages = self.getMessages(client,destination)
			messages.reverse()
			if (not(destinationUserData[4]==None)):
				lastLogin = (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(destinationUserData[4]))))
			else:
				lastLogin = ''
			destinationUserDetails = destination+'	'+'Last Login:'+lastLogin+' '+destinationUserData[6]
			
			userConversation = ''
			for message in messages:
				if (str(message[5])=='1'):
					userMessage = markdown.markdown(message[3])
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
		try:
			if(self.checkIfRateLimited(None,cherrypy.request.remote.ip)):
				return '11: Blacklisted or Rate Limited'
			client = cherrypy.session['username']	
			usersData = self.getAllUsersData()
			userDetails = ''
			for user in usersData:
				#print user[1]
				userDetails += ('''<div class="user"><button type="submit" class="msgBtn2" onclick="window.location.href='/openMessagingPage?destination='''+user[1]+''''">'''+user[1]+'''---'''+user[6]+'''</button><button type=submit class="msgBtn3" onclick="window.location.href='/viewProfilePage?username='''+user[1]+''''">View Profile</button></div>''')	
			Page = open('usersPage.html').read().format(userList = userDetails,username=client,userstatus=cherrypy.session['userStatus'])
			return Page
		except:	
			raise cherrypy.HTTPRedirect('/login') #redirect back to login page
	
	@cherrypy.expose
	def viewProfilePage(self,username=None):
		try:
			if(self.checkIfRateLimited(username,cherrypy.request.remote.ip)):
				return '11: Blacklisted or Rate Limited'
			client = cherrypy.session['username']
		except:
			raise cherrypy.HTTPRedirect('/login')
		finally:
			try:
				if username == None:
					#raise cherrypy.HTTPRedirect('/openUsersListPage')
					username = client
				if (client == username): #The current logged in user requesting to see their own profile page
					clientData = self.getClientProfile(client)
					
					Page = open('viewProfile.html').read().format(profileHeading = 'MY',UPI = client,fullname=clientData[2],position=clientData[3],description=clientData[4],location=clientData[5],image=clientData[6])
					return Page
				else:
					userData = self.getUserData(username)
					
					ip = userData[2]
					port = userData[5]
					
					#print'testProfilePage3'
					output_dict = {'sender':client,'profile_username':username}
					#print output_dict
					#print'testProfilePage3'
					data = json.dumps(output_dict) #data is a JSON object
					
					request = urllib2.Request('http://'+ ip + ':' + port + '/getProfile' , data, {'Content-Type':'application/json'})
					
					response = urllib2.urlopen(request,timeout=5).read()
					
					responseDict = (json.loads(response))
					#print responseDict
					Page = open('viewProfile.html').read().format(profileHeading = 'USER',UPI = username,fullname=responseDict['fullname'],position=responseDict['position'],description=responseDict['description'],location=responseDict['location'],image=responseDict['picture'])
					return Page
			except:
				#print'testProfilePage'
				Page = open('viewProfile.html').read().format(profileHeading = 'No data available for USER',UPI = username,fullname='',position='',description='',location='',image='')
				return Page
				#raise cherrypy.HTTPRedirect('/openUsersListPage')
		
	@cherrypy.expose
	def editProfile(self):#########################
		try:
			if(self.checkIfRateLimited(None,cherrypy.request.remote.ip)):
				return '11: Blacklisted or Rate Limited'
			
			Page = open('editProfile.html').read().format(clientUsername=cherrypy.session['username'])	
			return Page
		except:
			raise cherrypy.HTTPRedirect('/openUsersListPage')	
		
		
		#return open('messaging.html')	
    
	@cherrypy.expose
	def ping(self, sender=None):
		if(self.checkIfRateLimited(sender,cherrypy.request.remote.ip)):
			return '11: Blacklisted or Rate Limited'
		if (sender ==None):
			return '1: Missing Compulsory Field'
		else:	
			return '0'
	
	@cherrypy.expose
	@cherrypy.tools.json_in()
	def getProfile(self):
		try:
			
			input = cherrypy.request.json
			if((not('sender' in input))or(not('profile_username' in input))):
				return '1: Missing Compulsory Field'
			if(self.checkIfRateLimited(input['sender'],cherrypy.request.remote.ip)):
				return '11: Blacklisted or Rate Limited'	
			profileData = self.getClientProfile(input['profile_username'])
			outputDict = {'fullname':profileData[2],'position':profileData[3],'description':profileData[4], 'location':profileData[5], 'picture':profileData[6], 'encoding':profileData[7], 'encryption':profileData[8], 'decryptionKey': profileData[9]}
			return json.dumps(outputDict) #data is a JSON object
		except:
			return 'Error: Something Went Wrong'	

	
	@cherrypy.expose
	@cherrypy.tools.json_in()
	def receiveFile(self):
		try:
			
			
			input_data = cherrypy.request.json
			
			if(not('sender' in input_data))or(not('destination' in input_data))or(not('file' in input_data))or(not('stamp' in input_data)or(not('filename' in input_data))or(not('content_type' in input_data))):
				return '1: Missing Compulsory Field' ####WHAT  IF ONE OF THESE FIELDS IS EMPTY?
			
			if(self.checkIfRateLimited(input_data['sender'],cherrypy.request.remote.ip)):
				return '11: Blacklisted or Rate Limited'
			
			if('encryption' in input_data):
				if (not(str(input_data['encryption']) == '0')):
					return '9: Encryption Standard Not Supported' 
			print ('file sent from: '+input_data['sender'])
			base64Length = len(input_data['file'])
			fileLength = base64Length * 0.75
			#print fileLength
			if (fileLength>5242880):
				return ('4: File exceeds 5MB')
						
			inputFile = (input_data['file']).decode('base64')
			
			fileName = input_data['filename']
						
			if 'image/' in input_data['content_type']:
				fileMessage = '<img src="receivedFiles/'+fileName+'" alt= Picture 380x320 height="320" width="380">'	
			elif 'video/' in input_data['content_type']:
				fileMessage = '<video width="380" height="320" controls><source src="'+'receivedFiles/'+fileName+'">Your browser does not support the video tag.</video>'
			elif 'audio/' in input_data['content_type']:
				fileMessage = '<audio controls> <source src="'+'receivedFiles/'+fileName+'">Your browser does not support the audio element.</audio>'
			else:
				fileMessage = '<a href="receivedFiles/'+fileName+'" download>'+fileName +'</a>'
						
			self.insertIntoMessagesTable(input_data['sender'], input_data['destination'], fileMessage, input_data['stamp'], '0','true', fileName,input_data['content_type'])
			
			outFile = open('public/receivedFiles/'+fileName,'wb')
			outFile.write(inputFile)
			outFile.close
			print (fileName+' has been received')
			return ('0: Success')
		except:
			return ('Error: Something went wrong')
		
	@cherrypy.expose
	def sendFile(self, sender=None, destination=None, outFile=None,stamp = None,encryption=0, hashing = 0, hashedFile = None, decryptionKey=None):
		try:	
			if(self.checkIfRateLimited(username,cherrypy.request.remote.ip)):
				return '11: Blacklisted or Rate Limited'
			destinationUserData = self.getUserData(destination)
			ip = destinationUserData[2]
			port = destinationUserData[5]
			if (stamp == None)or(stamp== ''):
				stamp = float(time.time())
						
			fileName = outFile.filename
			content_type = outFile.content_type.value
			print (fileName + ' is preparing to be sent') 
			
			encoded = base64.b64encode(outFile.file.read())
			
			output_dict = {'sender':sender,'destination':destination,'file':encoded, 'stamp':stamp, 'filename':fileName,'content_type':content_type, 'encryption':encryption, 'hashing':hashing, 'hash': hashedFile}#, 'decryptionKey':decryptionKey}
			data = json.dumps(output_dict) #data is a JSON object
			request = urllib2.Request('http://'+ ip + ':' + port + '/receiveFile' , data, {'Content-Type':'application/json'})
			response = urllib2.urlopen(request,timeout=5)
			sendResponse = response.read()
			print ('file send response: '+sendResponse)
			if 'image/' in input_data['content_type']:
				fileMessage = '<img src="receivedFiles/'+fileName+'" alt= Picture 380x320 height="320" width="380">'	
			elif 'video/' in input_data['content_type']:
				fileMessage = '<video width="380" height="320" controls><source src="'+'receivedFiles/'+fileName+'">Your browser does not support the video tag.</video>'
			elif 'audio/' in input_data['content_type']:
				fileMessage = '<audio controls> <source src="'+'receivedFiles/'+fileName+'">Your browser does not support the audio element.</audio>'
			else:
				fileMessage = '<a href="receivedFiles/'+fileName+'" download>'+fileName +'</a>'
			
			self.insertIntoMessagesTable(output_dict['sender'], output_dict['destination'], fileMessage, output_dict['stamp'], '0','true', fileName, content_type)
			
			if (str(sendResponse[0]) == '0')or(str(sendResponse[1]) == '0'):
				
				saveFile = open('public/receivedFiles/'+fileName,'wb')
				saveFile.write((output_dict['file']).decode('base64'))
				saveFile.close
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
		if(self.checkIfRateLimited(username,cherrypy.request.remote.ip)):
			return '11: Blacklisted or Rate Limited'
		
		hashOfPasswordPlusSalt = None
		if(not(password==None)):
			passwordPlusSalt = password + SALT
			hashOfPasswordPlusSalt = hashlib.sha256(passwordPlusSalt).hexdigest()
		error = self.authoriseUserLogin(username,hashOfPasswordPlusSalt)
		if (error == 0):
			cherrypy.session['username'] = username;
			cherrypy.session['hashedPassword'] = hashOfPasswordPlusSalt;
			cherrypy.session['userStatus'] = 'Online'
			self.currentUser = cherrypy.session['username']
			self.currentUserHashedPassword = cherrypy.session['hashedPassword']
			self.openUsersListPage()############################################################################################################################
			
			self.serverReportThreading(cherrypy.session['username'],cherrypy.session['hashedPassword'])
			raise cherrypy.HTTPRedirect('/openUsersListPage')
		else:
			cherrypy.session['loginStatusText'] = "Username or Password is Incorrect"
			raise cherrypy.HTTPRedirect('/login')

	@cherrypy.expose
	def signout(self,serverShutDown = False):
		"""Logs the current user out, expires their session"""
		if(self.checkIfRateLimited(None,cherrypy.request.remote.ip)):
			return '11: Blacklisted or Rate Limited'
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
				
				
				cherrypy.lib.sessions.expire()			
			redirectToLoginPage = True			
		except:			
			try:
				cherrypy.lib.sessions.expire()
			except:
				pass
			redirectToLoginPage = True
			
		if(serverShutDown == True):
			return			
		if(redirectToLoginPage):
			raise cherrypy.HTTPRedirect('/login')
		
	def serverExitLogOff(self):
		print('Server Exit Procedure Initiated')
		self.signout(True)	
        
	def serverReportThreading(self,username,hashedPassword):
		thread.start_new_thread(self.serverReportTimer, (username,hashedPassword))
		
		
	def serverReportTimer(self,username,hashedPassword):
		beginTime=time.time()
		loop = True
		
		while (loop == True):
			time.sleep(30.0-((time.time()-beginTime)%30.0))#how many secs there are to the nearest 30 sec block of time, 30 minus that to figure out how long you have to sleep, the reason I do this is to account for variable execution times for self.authoriseUserLogin()
			#print (self.checkIfStillLoggedIn(username,hashedPassword))
			if(self.checkIfStillLoggedIn(username,hashedPassword)):	
				try:
					self.clearRateRequestTable()
					self.authoriseUserLogin(username,hashedPassword)
				except:
					pass	
			else:			
				loop = False
		print 'server login report thread exited'
		thread.exit()		
	
	def checkIfStillLoggedIn(self, username=None, hashedPassword=None):
		try:
			ip = self.getIP()
			location = self.getLocation(ip)
			onlineUsersRequest = urllib2.Request('http://cs302.pythonanywhere.com/getList?username='+username+'&password='+hashedPassword+'&enc=0&json=1')
			onlineUsersResponse = urllib2.urlopen(onlineUsersRequest)
			onlineUsersData = onlineUsersResponse.read()
			onlineUsersData = json.loads(onlineUsersData)
			#print onlineUsersData
			for value in onlineUsersData.itervalues():
				#print value['username']
				#print username
				if(value['username']==username):
					return True
			
		except:
			pass
		return False
	
	def authoriseUserLogin(self, username=None, hashedPassword=None):
		try:
			ip = self.getIP()
			location = self.getLocation(ip)
			if ((username==None)or(username=='')or(hashedPassword==None)or(hashedPassword=='')):
				return 1	
				
			loginRequest = urllib2.Request('http://cs302.pythonanywhere.com/report?username='+username+'&password='+hashedPassword+'&location='+location+'&ip='+ip+'&port='+str(listen_port)+'&enc=0')	#Object which represents the HTTP request we are making
			
			loginResponse = urllib2.urlopen(loginRequest,timeout=10)#Returns a response object for the requested URL
			loginData = loginResponse.read() #The response is a file-like object, so .read() can be called on it
			
			
			print ('Server login report: '+loginData)
			
			
			if(loginData[0]=='0'):
				onlineUsersRequest = urllib2.Request('http://cs302.pythonanywhere.com/getList?username='+username+'&password='+hashedPassword+'&enc=0&json=1')
				onlineUsersResponse = urllib2.urlopen(onlineUsersRequest,timeout=5)
				onlineUsersData = onlineUsersResponse.read()
				
				self.updateAllUsersTable(onlineUsersData)
				
			
			
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
		try:
			
				
			input = cherrypy.request.json
			if(not('requestor' in input)):
				return '1: Missing Compulsory Field'
			elif((input['requestor'])==None)or((input['requestor'])==''):	
				return '1: Missing Compulsory Field'
			requestor = input['requestor']	
			
			if(self.checkIfRateLimited(input['requestor'],cherrypy.request.remote.ip)):
				return '11: Blacklisted or Rate Limited'
			
			messagesForRequestor = self.getMessagesForOneUser(requestor)
			for message in messagesForRequestor:
				#stamp = ((message[4]).encode('utf-8'))
				stamp = message[4]
				if (message[6]=='false'):#send message
					self.sendMessage(message[1], message[2], message[3],message[5],float(stamp))
				elif (message[6]=='true'):
					fileName = message[7]
								
			return '0: Success'
		except:
			return 'Error: Something Went Wrong'#client unavailable?	
	
	@cherrypy.expose
	def openSetUserStatusPage(self):
		try:
			if(self.checkIfRateLimited(None,cherrypy.request.remote.ip)):
				return '11: Blacklisted or Rate Limited'
			
			username = cherrypy.session['username']
			Page = open('editUserStatus.html')
			return Page
		except:
			pass
		raise cherrypy.HTTPRedirect('/openUsersListPage')
	
	@cherrypy.expose
	def setUserStatus(self,userStatus = 'Online'):
		try:
			if(self.checkIfRateLimited(None,cherrypy.request.remote.ip)):
				return '11: Blacklisted or Rate Limited'
		
			cherrypy.session['userStatus'] = userStatus
			conn = sqlite3.connect(DB_USER_DATA)
			c = conn.cursor()
			c.execute('''UPDATE AllUsers SET status = ? WHERE username = ?''',(userStatus, cherrypy.session['username']))
			conn.commit() # commit actions to the database
			conn.close()	
			
		except:
			pass
		raise cherrypy.HTTPRedirect('/openUsersListPage')

		
	
	@cherrypy.expose
	@cherrypy.tools.json_in()
	def getStatus(self):	
		try:
			if(self.checkIfRateLimited(None,cherrypy.request.remote.ip)):
				return '11: Blacklisted or Rate Limited'
			
			input = cherrypy.request.json
			if(not('profile_username' in input)):				
				return '1: Missing Compulsory Field'
			userStatus = self.getUserData(input['profile_username'])
			
			outputDict = {'status':userStatus[6]}
			return json.dumps(outputDict)
		except:
			return '3: Client Currently Unavailable'
	
	@cherrypy.expose
	def requestOfflineMessages(self):######################################################################################
		try:
			if(self.checkIfRateLimited(None,cherrypy.request.remote.ip)):
				return '11: Blacklisted or Rate Limited'
			
			username = cherrypy.session['username']
			hashedPassword = cherrypy.session['hashedPassword']
			
			onlineUsersRequest = urllib2.Request('http://cs302.pythonanywhere.com/getList?username='+username+'&password='+hashedPassword+'&enc=0&json=1')
			onlineUsersResponse = urllib2.urlopen(onlineUsersRequest,timeout=5)
			onlineUsersData = onlineUsersResponse.read()
			onlineUsersData = json.loads(onlineUsersData)
			
			output_dict = {'requestor':username}
			data = json.dumps(output_dict) #data is a JSON object
			
			for value in onlineUsersData.itervalues():
				try:
					userToRequest = value['username']
					if (not(userToRequest == username)):
						destinationUserData = self.getUserData(userToRequest)
						ip = destinationUserData[2]
						port = destinationUserData[5]
						
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
		
		try:
			
			
			input_data = cherrypy.request.json
			
			
			if(not('sender' in input_data))or(not('destination' in input_data))or(not('message' in input_data))or(not('stamp' in input_data)):
				return '1: Missing Compulsory Field' ####WHAT  IF ONE OF THESE FIELDS IS EMPTY?
			
			if(self.checkIfRateLimited(input_data['sender'],cherrypy.request.remote.ip)):
				return '11: Blacklisted or Rate Limited'
			
			if('encryption' in input_data):
				if (not(str(input_data['encryption']) == '0')):
					#encryption = input_data['encryption']
				#else:
					return '9: Encryption Standard Not Supported' 
			
			markDown='0'
			if ('markdown' in input_data):
				if ((str(input_data['markdown'])) == '1'):
					#print 'receiveMessageTest1'
					message = markdown.markdown(input_data['message'])
					markDown = '1'
					#print 'receiveMessageTesta'
				else:
					#print 'receiveMessageTest2'
					message = input_data['message'] 
			else:
				#print 'receiveMessageTest3'
				message = input_data['message'] 
			#print 'receiveMessageTest'
							
			#print input_data
			self.insertIntoMessagesTable(input_data['sender'], input_data['destination'], message, input_data['stamp'], markDown,'false', None,None)
			return ('0: Success')
		except Exception as e: 
			print e
			return ('Error: Something went wrong')
		
	@cherrypy.expose
	def sendMessage(self, sender=None, destination=None, message='Default Message',markDown='0',stamp=None,encryption=0, hashing = 0, hashedMessage = None, decryptionKey=None):	
		data = None
		try:	
			if(self.checkIfRateLimited(sender,cherrypy.request.remote.ip)):
				return '11: Blacklisted or Rate Limited'
			
			if ((message == None)or(message == '')):
				raise cherrypy.HTTPRedirect('/openMessagingPage?destination='+destination)
			destinationUserData = self.getUserData(destination)
			
			ip = destinationUserData[2]
			port = destinationUserData[5]
			
			if (stamp == None)or(stamp== ''):
				stamp = float(time.time())
			output_dict = {'sender':sender,'destination':destination,'message':message, 'stamp':stamp, 'markdown':int(markDown), 'encryption':encryption, 'hashing':hashing, 'hash': hashedMessage, 'decryptionKey':decryptionKey}
			data = json.dumps(output_dict) #data is a JSON object
			
			request = urllib2.Request('http://'+ ip + ':' + port + '/receiveMessage', data, {'Content-Type':'application/json'})
			response = urllib2.urlopen(request,timeout=5)
			#print 'sendMessageTest'
			if (str(markDown)=='1'):
				message = markdown.markdown(output_dict['message'])
			
			
			self.insertIntoMessagesTable(output_dict['sender'], output_dict['destination'], message, output_dict['stamp'], int(markDown),'false', None,None)
			print response.read()
		except Exception as e: 
			print e
			print 'send message error'
			if(sender==None)or(destination==None):
				raise cherrypy.HTTPRedirect('/login')
		#redirect back to messaging page
		raise cherrypy.HTTPRedirect('/openMessagingPage?destination='+destination)	
	
	
	#WEB_ROOT = os.path.join(os.getcwd(), 'public') 

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
