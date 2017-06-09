#!/usr/bin/python
""" cherrypy_example.py

    COMPSYS302 - Software Design
    Author: Andrew Chen (andrew.chen@auckland.ac.nz)
    Last Edited: 19/02/2015

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
from cherrypy.process.plugins import Monitor
import thread
import base64
import markdown
from operator import xor

class MainApp(object):
			
	def getLocation(self,ip):
		if (('130.216.' in ip)or('10.103.' in ip)or('10.104.' in ip)):########
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
		#socket.gethostbyname(socket.gethostname())	#internal ip address	
		externalIP = (urllib2.urlopen(urllib2.Request('http://ident.me'))).read().decode('utf8') #retrieves external ip	#encrypt?
		#print internalIP
		#print externalIP
		location = self.getLocation(internalIP)
		#print location
		if((location == '0')or(location == '1')):
			#print 'testing!!!!!!!!'
			return str(internalIP)
		else:
			return str(externalIP)
	
	
	def createClientProfilesTable():
		conn = sqlite3.connect(DB_USER_DATA)
		
		# Database will have UTF-8 encoding
		#conn.text_factory = str
		
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
			c.execute("INSERT INTO ClientProfiles (profile_username,picture) SELECT ?,'https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_960_720.png' WHERE NOT EXISTS (SELECT * FROM ClientProfiles WHERE profile_username = ?)", (UPI,UPI))
		
		conn.commit() # commit actions to the database
		conn.close()
	
	def getClientProfile(self,profile_username=''):
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		c.execute('''SELECT * FROM ClientProfiles WHERE profile_username = ?''', (profile_username,))
		profileData = c.fetchone()
		conn.close()
		#print profileData
		return profileData
		
	def getUserData(self,username=''):
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		c.execute('''SELECT * FROM AllUsers WHERE username = ?''', (username,))
		userData = c.fetchone()
		conn.close()
		print 'test'
		print userData
		print 'test'
		return userData	
	
	@cherrypy.expose######################
	def updateClientProfileDetails(self,username=None, fullname=None, position=None, description=None, location=None, picture=None):
		""" """
		#username = cherrypy.session['username']
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
		#error = self.authoriseUserLogin(username,password)
		#if (error == 0):
		#    cherrypy.session['username'] = username;
		raise cherrypy.HTTPRedirect('/')
		#else:
		#    raise cherrypy.HTTPRedirect('/login')
	
	def createMessagesTable():
		conn = sqlite3.connect(DB_USER_DATA)
		
		# Database will have UTF-8 encoding
		#conn.text_factory = str
		
		# Once we have a Connection, we can create a Cursor object and call its execute() method to perform SQL commands
		c = conn.cursor()
		
		c.execute('''CREATE TABLE IF NOT EXISTS Messages (id INTEGER PRIMARY KEY, sender TEXT, destination TEXT, message TEXT, stamp TEXT, markdown TEXT, isFile TEXT, fileLink TEXT, fileType TEXT, fileName TEXT)''')
		
		conn.commit()
		conn.close()
	
	def getMessages(self,sender, destination):
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		c.execute('''SELECT * FROM Messages WHERE ((sender=? AND destination=?)OR (sender=? AND destination=?)) order by stamp ''',(sender,destination,destination,sender))
		messages = c.fetchall()
		conn.commit()
		conn.close()
		#return (sentMessages, receivedMessages)
		#print messages
		for message in messages:
			#print message[4]
			#message[4]=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(message[4])))
			print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(message[4]))))
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
		
		# Database will have UTF-8 encoding
		#conn.text_factory = str
		
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
		for UPI in serversUsersList:		
			c.execute("INSERT INTO AllUsers (username) SELECT ? WHERE NOT EXISTS (SELECT * FROM AllUsers WHERE username = ?)", (UPI,UPI))
		
		conn.commit() # commit actions to the database
		conn.close()
		

		
	def updateAllUsersTable(self, onlineUsersData):
		onlineUsersData = json.loads(onlineUsersData)
		
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		c.execute("UPDATE AllUsers SET status = 'Logged Off'")
		for value in onlineUsersData.itervalues():
		
			c.execute('''UPDATE AllUsers SET ip = ? , location = ?, lastLogin = ?, port = ?, status = 'Logged On' WHERE username = ?''', (value['ip'], value['location'], value['lastLogin'], value['port'], value['username']))
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
	#lock = thread.allocate_lock()
	#IP = getIP()	
	
	#webbrowser.open_new('http://%s:%d/' % (listen_ip, listen_port)) # Opens web browser            
	#CherryPy Configuration
	
	#_cp_config = {'tools.encode.on': True, 
                  #'tools.encode.encoding': 'utf-8',
                  #'tools.sessions.on' : 'True',
                 #}             
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
				
		return '/receiveMessage [sender] [destination] [message] [stamp] [markdown(opt)] [markdown(opt)] [encoding(opt)] [encryption(opt)] [hashing(opt)] [hash(opt)] [decryptionKey(opt)] Encoding <>  Encryption <>  Hashing <>'
        
	@cherrypy.expose
	def login(self):
		try:
			Page = open('login.html').read().format(statusText = cherrypy.session['loginStatusText'])
		except:
			Page = open('login.html').read().format(statusText = 'Enter your Username and Password')	
		#Page = open('usersPage.html')
		return Page
	
	@cherrypy.expose
	def openMessagingPage(self,destination=None):
		try:
			client = cherrypy.session['username']
			destinationUserData = self.getUserData(destination)
			messages = self.getMessages(client,destination)
			messages.reverse()
			if (not(destinationUserData[4]==None)):
				lastLogin = (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(destinationUserData[4]))))
			else:
				lastLogin = ''
			destinationUserDetails = destination+'	'+'Last Login: '+lastLogin
			#userConversation = '<li class="i"> <div class="head"> <span class="time">10:13 AM, Today</span> <span class="name">You</span> </div> <div class="message">Initial</div>  </li>'
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
		
		
	@cherrypy.expose
	def openUsersListPage(self):
		try:
			client = cherrypy.session['username']	
			usersData = self.getAllUsersData()
			userDetails = ''
			for user in usersData:
				#print user[1]
				userDetails += ('''<div class="user"><button type="submit" class="msgBtn2" onclick="window.location.href='/openMessagingPage?destination='''+user[1]+''''">'''+user[1]+'''---'''+user[6]+'''</button><button type=submit class="msgBtn3" onclick="window.location.href='/viewProfilePage?username='''+user[1]+''''">View Profile</button></div>''')	
			Page = open('usersPage.html').read().format(userList = userDetails,username=client)
			return Page
		except:	
			raise cherrypy.HTTPRedirect('/login') #redirect back to login page
	
	@cherrypy.expose
	def viewProfilePage(self,username=None):
		try:
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
					
					print'testProfilePage3'
					output_dict = {'sender':client,'profile_username':username}
					print output_dict
					print'testProfilePage3'
					data = json.dumps(output_dict) #data is a JSON object
					
					request = urllib2.Request('http://'+ ip + ':' + port + '/getProfile' , data, {'Content-Type':'application/json'})
					
					response = urllib2.urlopen(request,timeout=5).read()
					
					responseDict = (json.loads(response))
					print responseDict
					Page = open('viewProfile.html').read().format(profileHeading = 'USER',UPI = username,fullname=responseDict['fullname'],position=responseDict['position'],description=responseDict['description'],location=responseDict['location'],image=responseDict['picture'])
					return Page
			except:
				print'testProfilePage'
				Page = open('viewProfile.html').read().format(profileHeading = 'No data available for USER',UPI = username,fullname='',position='',description='',location='',image='')
				return Page
				#raise cherrypy.HTTPRedirect('/openUsersListPage')
		
	@cherrypy.expose
	def editProfile(self):#########################
		try:
			Page = open('editProfile.html').read().format(clientUsername=cherrypy.session['username'])	
			return Page
		except:
			raise cherrypy.HTTPRedirect('/openUsersListPage')	
		
		
		#return open('messaging.html')	
    
	@cherrypy.expose
	def ping(self, sender=None):
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
			print input_data['sender']
			base64Length = len(input_data['file'])
			fileLength = base64Length * 0.75
			print fileLength
			if (fileLength>5242880):
				return ('4: File exceeds 5MB')
			#print ((len(input_data['file'])*(3/4)))
			
			inputFile = (input_data['file']).decode('base64')
			#os.path.getsize(inputFile)
			fileName = input_data['filename']#
			
			print 'test point'
			#fileMessage = '<a href="'+'receivedFiles/'+fileName
			#<img src="http://www.robotspacebrain.com/wp-content/uploads/2013/05/Daft-Punk-Helmet-GIFs-6.gif" alt="Profile Picture 380x420" height="420" width="380">
			if 'image/' in input_data['content_type']:
				fileMessage = '<img src="receivedFiles/'+fileName+'" alt= Picture 250x200 height="200" width="250">'	
			elif 'video/' in input_data['content_type']:
				fileMessage = '<video width="250" height="200" controls><source src="'+'receivedFiles/'+fileName+'">Your browser does not support the video tag.</video>'
			elif 'audio/' in input_data['content_type']:
				fileMessage = '<audio controls> <source src="'+'receivedFiles/'+fileName+'">Your browser does not support the audio element.</audio>'
			else:
				fileMessage = '<a href="receivedFiles/'+fileName+'" download>'+fileName +'</a>'
			
			
			#fileMessage = '<img src="'+'receivedFiles/'+fileName+'" alt= Picture 380x320 height="320" width="380">'
			self.insertIntoMessagesTable(input_data['sender'], input_data['destination'], fileMessage, input_data['stamp'], '0','true', fileName,input_data['content_type'])
			print fileName
			outFile = open('public/receivedFiles/'+fileName,'wb')
			print (fileName+'2')
			outFile.write(inputFile)
			outFile.close
			return ('0: Success')
		except:
			return ('Error: Something went wrong')
		
	@cherrypy.expose
	def sendFile(self, sender='smoh944', destination=None, outFile=None,ip='10.103.137.62',port='10001',content_type=None,filename=None,encryption=0, hashing = 0, hashedFile = None, decryptionKey=None):
		try:	
			#destination='abha808'
			destinationUserData = self.getUserData(destination)
			ip = destinationUserData[2]
			port = destinationUserData[5]
			#print destinationUserData[2]
			#print destinationUserData[5]
			sender='smoh944'
			#destination='abha808'
			fileName = outFile.filename
			content_type = outFile.content_type.value
			print (fileName + ' is preparing to be sent') 
			#file='HelloThisisaTest'
			encoded = base64.b64encode(outFile.file.read())
			print fileName
			output_dict = {'sender':sender,'destination':destination,'file':encoded, 'stamp':float(time.time()), 'filename':fileName,'content_type':content_type, 'encryption':encryption, 'hashing':hashing, 'hash': hashedFile}#, 'decryptionKey':decryptionKey}
			data = json.dumps(output_dict) #data is a JSON object
			request = urllib2.Request('http://'+ ip + ':' + port + '/receiveFile' , data, {'Content-Type':'application/json'})
			response = urllib2.urlopen(request,timeout=5)
			print ('file send response: '+response.read())
			if 'image/' in content_type:
				print 'imagetest'
				fileMessage = '<img src="receivedFiles/'+fileName+'" alt= "Picture 380x320" height="320" width="380">'	
				#fileMessage = '''<img src="receivedFiles/maxresdefault.jpg" alt= Picture 380x320 height="320" width="380">'''
			elif 'video/' in content_type:
				fileMessage = '<video width="380" height="320" controls><source src="'+'receivedFiles/'+fileName+'">Your browser does not support the video tag.</video>'
			elif 'audio/' in content_type:
				fileMessage = '<audio controls> <source src="'+'receivedFiles/'+fileName+'">Your browser does not support the audio element.</audio>'
			else:
				fileMessage = '<a href="receivedFiles/'+fileName+'" download>'+fileName +'</a>'
			
			self.insertIntoMessagesTable(output_dict['sender'], output_dict['destination'], fileMessage, output_dict['stamp'], '0','true', fileName, content_type)
			saveFile = open('public/receivedFiles/'+fileName,'wb')
			print (fileName+'2')
			saveFile.write((output_dict['file']).decode('base64'))
			saveFile.close
			
		except:
			print 'file send error'
			if(sender==None)or(destination==None):
				raise cherrypy.HTTPRedirect('/login')
		raise cherrypy.HTTPRedirect('/openMessagingPage?destination='+destination)	
		#redirect back to destination user page
	#@cherrypy.expose
	#def messageUserPage(self,destination = ''):
		#Page = open('messaging.html').read().format(receiverUsername = destination)
	
	@cherrypy.expose
	def viewOnlineUsers(self):
		""" """
		#self.authoriseUserLogin()
		try:
			Page = 'Users: '+cherrypy.session['onlineUsersData']+'<br/>'	
		except KeyError: #There is no online user list
			Page = 'No online user data available at this time<br/>'   
		    
		
		return Page
	
	
        
	# LOGGING IN AND OUT
	@cherrypy.expose
	def signin(self, username=None, password=None):
		"""Check their name and password and send them either to the main page, or back to the 			main login screen."""
		hashOfPasswordPlusSalt = None
		if(not(password==None)):
			passwordPlusSalt = password + SALT
			hashOfPasswordPlusSalt = hashlib.sha256(passwordPlusSalt).hexdigest()
		error = self.authoriseUserLogin(username,hashOfPasswordPlusSalt)
		if (error == 0):
			cherrypy.session['username'] = username;
			cherrypy.session['hashedPassword'] = hashOfPasswordPlusSalt;
			#self.sendMessage()
			self.openUsersListPage()
			#self.getMessages('smoh944', 'abha808')
			self.serverReportThreading(cherrypy.session['username'],cherrypy.session['hashedPassword'])
			raise cherrypy.HTTPRedirect('/openUsersListPage')
		else:
			cherrypy.session['loginStatusText'] = "Username or Password is Incorrect"
			raise cherrypy.HTTPRedirect('/login')

	@cherrypy.expose
	def signout(self):
		"""Logs the current user out, expires their session"""
		username = cherrypy.session.get('username')
		if (username == None):
			pass
		else:		    
			#url = 'https://cs302.pythonanywhere.com/logoff?username=' + cherrypy.session['username'] + '&password=' + cherrypy.session['hashedPassword'] + '&enc=0'
			logoutRequest = urllib2.Request('https://cs302.pythonanywhere.com/logoff?username=' + cherrypy.session['username'] + '&password=' + cherrypy.session['hashedPassword'] + '&enc=0')
			logoutResponse = urllib2.urlopen(logoutRequest,timeout=10)	
			logoutData = logoutResponse.read()
			print logoutData
			cherrypy.lib.sessions.expire()
		raise cherrypy.HTTPRedirect('/login')
        
	def serverReportThreading(self,username,hashedPassword):
		thread.start_new_thread(self.serverReportTimer, (username,hashedPassword))

	def serverReportTimer(self,username,hashedPassword):
		beginTime=time.time()
		while True:
			time.sleep(30.0-((time.time()-beginTime)%30.0))#how many secs there are to the nearest 50 sec block of time, 50 minus that to figure out how long you have to sleep, the reason I do this is to account for variable execution times for self.authoriseUserLogin()
			try:
				self.authoriseUserLogin(username,hashedPassword)
			except:
				pass	
	
	def authoriseUserLogin(self, username=None, hashedPassword=None):
		#if(not(password==None)):
			#passwordPlusSalt = password + SALT
			#hashOfPasswordPlusSalt = hashlib.sha256(passwordPlusSalt).hexdigest()
			#print hashOfPasswordPlusSalt

		#2cc4ba400f5105057f065f06ae9d758eb4388783038d738d6684666cb4297751
		#smoh944
		ip = self.getIP()
		location = self.getLocation(ip)
		if ((username==None)or(username=='')or(hashedPassword==None)or(hashedPassword=='')):
			return 1	
			
		loginRequest = urllib2.Request('http://cs302.pythonanywhere.com/report?username='+username+'&password='+hashedPassword+'&location='+location+'&ip='+ip+'&port='+str(listen_port)+'&enc=0')	#Object which represents the HTTP request we are making
		#loginRequest = urllib2.Request('http://cs302.pythonanywhere.com/report?username='+username+'&password='+hashOfPasswordPlusSalt+'&location=2&ip=118.92.154.45&port=10001&enc=0')
		loginResponse = urllib2.urlopen(loginRequest,timeout=10)#Returns a response object for the requested URL
		loginData = loginResponse.read() #The response is a file-like object, so .read() can be called on it
		
		#print loginData
		print loginData
		#print cherrypy.session.id
		#print password
		
		if(loginData[0]=='0'):
			onlineUsersRequest = urllib2.Request('http://cs302.pythonanywhere.com/getList?username='+username+'&password='+hashedPassword+'&enc=0&json=1')
			onlineUsersResponse = urllib2.urlopen(onlineUsersRequest)
			onlineUsersData = onlineUsersResponse.read()
			#self.lock.acquire()
			self.updateAllUsersTable(onlineUsersData)
			#self.lock.release()
		
		#print onlineUsersData
			#cherrypy.session['onlineUsersData'] = onlineUsersData;
		#self.setupDatabase()
		#self.populateAllUsersTable()
		#self.getClientProfile()
		
		#self.insertIntoMessagesTable('smoh944', 'abha808', 'testingadil', float(time.time()), '0','false', None)
		
		#self.sendMessage()
		#self.sendFile()
		if (loginData[0] == "0") :
			return 0
		else:
		    return 1

	@cherrypy.expose
	@cherrypy.tools.json_in()
	def receiveMessage(self):
		
		try:
			input_data = cherrypy.request.json
			print input_data
			#return '0: '
			if(not('sender' in input_data))or(not('destination' in input_data))or(not('message' in input_data))or(not('stamp' in input_data)):
				return '1: Missing Compulsory Field' ####WHAT  IF ONE OF THESE FIELDS IS EMPTY?
			markDown='0'
			if ('markdown' in input_data):
				if ((str(input_data['markdown'])) == '1'):
					print 'receiveMessageTest1'
					message = markdown.markdown(input_data['message'])
					print 'receiveMessageTesta'
				else:
					print 'receiveMessageTest2'
					message = input_data['message'] 
			else:
				print 'receiveMessageTest3'
				message = input_data['message'] 
			print 'receiveMessageTest'
			if('encryption' in input_data):
				if (not(str(input_data['encryption']) == '0')):
					#encryption = input_data['encryption']
				#else:
					return '9: Encryption Standard Not Supported' 	
				
			print input_data
			self.insertIntoMessagesTable(input_data['sender'], input_data['destination'], message, input_data['stamp'], markDown,'false', None,None)
			return ('0: Success')
		except Exception as e: 
			print e
			return ('Error: Something went wrong')
		
	@cherrypy.expose
	#def sendMessage(self, sender='smoh944', destination='abha808', message='Hello This is a Test',ip='172.24.26.17',port='10001',markdown='0',encoding='0',encryption='0', hashing = '0', hashedMessage = '', decryptionKey='0'):
	def sendMessage(self, sender=None, destination=None, message='Default Message',markDown='0',encryption=0, hashing = 0, hashedMessage = None, decryptionKey=None):	
		try:	
			if ((message == None)or(message == '')):
				raise cherrypy.HTTPRedirect('/openMessagingPage?destination='+destination)
			destinationUserData = self.getUserData(destination)
			ip = destinationUserData[2]
			port = destinationUserData[5]
			#print destination	
			output_dict = {'sender':sender,'destination':destination,'message':message, 'stamp':float(time.time()), 'markdown':int(markDown), 'encryption':encryption, 'hashing':hashing, 'hash': hashedMessage, 'decryptionKey':decryptionKey}
			data = json.dumps(output_dict) #data is a JSON object
			request = urllib2.Request('http://'+ ip + ':' + port + '/receiveMessage', data, {'Content-Type':'application/json'})
			response = urllib2.urlopen(request,timeout=5)
			print 'sendMessageTest'
			
			self.insertIntoMessagesTable(output_dict['sender'], output_dict['destination'], output_dict['message'], output_dict['stamp'], int(markDown),'false', None,None)
			print response.read()
		except Exception as e: 
			print e
			print 'send message error'
			if(sender==None)or(destination==None):
				raise cherrypy.HTTPRedirect('/login')
		#redirect back to messaging page
		raise cherrypy.HTTPRedirect('/openMessagingPage?destination='+destination)	
		
	WEB_ROOT = os.path.join(os.getcwd(), 'public') 

	cherrypy.config.update({'error_page.404': default,'server.socket_host': '127.0.0.1','server.socket_port': 10001,'engine.autoreload.on': True,'tools.sessions.on': True,'tools.encode.on': True,'tools.encode.encoding': 'utf-8','tools.staticdir.on' : True,	'tools.staticdir.dir' : WEB_ROOT,'tools.staticdir.index' : 'login.html'})
          
def runMainApp():
	"""
	config = {
		 '/': {
		     'tools.sessions.on': True,#enabling sessions
		     'tools.staticdir.root': os.path.abspath(os.getcwd()),#gets the absolute path to this folder
			 'tools.staticdir.on': True, #enabling a static directory which will serve static content to all of my webpages
		     'tools.staticdir.dir': './public'#static directory maps into public folder
			
		 },
		 '/generator': {
		     'request.dispatch': cherrypy.dispatch.MethodDispatcher(),
		     'tools.response_headers.on': True,
		     'tools.response_headers.headers': [('Content-Type', 'text/plain')],
		 }#,
		 #'/static': {	 
		     #'tools.staticdir.on': True, #enabling a static directory which will serve static content to all of my webpages
		     #'tools.staticdir.dir': './public'#static directory maps into public folder
		 #}
	}
	""" 
	#print os.path.abspath(os.getcwd())
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
