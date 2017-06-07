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
#import markdown
from operator import xor

class MainApp(object):
			
	def getLocation(self,ip):
		if (('130.216.' in ip)or('10.103.' in ip)or('10.104.' in ip)):
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
		print internalIP
		print externalIP
		location = self.getLocation(internalIP)
		print location
		if((location == '0')or(location == '1')):
			print 'testing!!!!!!!!'
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
		serverUsersResponse = urllib2.urlopen(serverUsersRequest)
		serverUsersData = serverUsersResponse.read()
		serversUsersList = serverUsersData.split(',')
		
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		for UPI in serversUsersList:		
			c.execute("INSERT INTO ClientProfiles (profile_username,picture) SELECT ?,'https://pixabay.com/p-973460/?no_redirect' WHERE NOT EXISTS (SELECT * FROM ClientProfiles WHERE profile_username = ?)", (UPI,UPI))
		
		conn.commit() # commit actions to the database
		conn.close()
	
	def getClientProfile(self,profile_username='smoh944'):
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		c.execute('''SELECT * FROM ClientProfiles WHERE profile_username = ?''', (profile_username,))
		profileData = c.fetchone()
		conn.close()
		print profileData
		return profileData
	
	@cherrypy.expose######################
	def updateClientProfileDetails(self, fullname=None, position=None, description=None, location=None, picture=None):
		""" """
		username = cherrypy.session['username']
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
		
		c.execute('''CREATE TABLE IF NOT EXISTS Messages (id INTEGER PRIMARY KEY, sender TEXT, destination TEXT, message TEXT, stamp TEXT, markdown TEXT, encoding TEXT, encryption TEXT, hashing TEXT, hash TEXT, decryptionKey TEXT)''')
		
		conn.commit()
		conn.close()
	
	def insertIntoMessagesTables(self, sender = None, destination = None, message = None, stamp = None):	
		pass
		
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
		serverUsersResponse = urllib2.urlopen(serverUsersRequest)
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
		c.execute("UPDATE AllUsers SET status = 'offline'")
		for value in onlineUsersData.itervalues():
		
			c.execute('''UPDATE AllUsers SET ip = ? , location = ?, lastLogin = ?, port = ?, status = 'online' WHERE username = ?''', (value['ip'], value['location'], value['lastLogin'], value['port'], value['username']))
			try:
				c.execute('''UPDATE AllUsers SET publicKey = ? WHERE username = ?''',(value['publicKey'], value['username']))
			except:
				pass
		conn.commit() # commit actions to the database
		conn.close()
		
	

	

	
	
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
		Page = "Welcome! This is a test website for COMPSYS302!<br/>"
		
		try:
			Page += "Hello " + cherrypy.session['username'] + "!<br/>"
			Page += "Here is some bonus text because you've logged in!"
			
			Page += "Click here to <a href='editProfile'>Edit Profile</a>."
			
			Page += '<form action="/viewOnlineUsers" method="post" enctype="multipart/form-data">'
			Page += '<input type="submit" value="List of online users"/></form>'
		except KeyError: #There is no username
		    
		    Page += "Click here to <a href='login'>login</a>."
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
		#Page = open('index.html')
		return Page
		
	@cherrypy.expose
	def editProfile(self):#########################
		#return open('editProfile.html')
		return open('messaging.html')	
    
	@cherrypy.expose
	def ping(self, sender=None):
		return '0'
	
	@cherrypy.expose
	@cherrypy.tools.json_in()
	def getProfile(self):
		input = cherrypy.request.json
		profileData = self.getClientProfile(input['profile_username'])
		outputDict = {'fullname':profileData[2],'position':profileData[3],'description':profileData[4], 'location':profileData[5], 'picture':profileData[6], 'encoding':profileData[7], 'encryption':profileData[8], 'decryptionKey': profileData[9]}
		return json.dumps(outputDict) #data is a JSON object

	
	@cherrypy.expose
	@cherrypy.tools.json_in()
	def receiveFile(self, encoding = 0):
		try:
			input_data = cherrypy.request.json
			print input_data['sender']
			return ('0: Success')
		except:
			return ('Error: Something went wrong')
		
	@cherrypy.expose
	def sendFile(self, sender='smoh944', destination='abha808', file='Hello This is a Test',ip='172.24.26.17',port='10001',content_type='text',filename='test.txt',encoding='0',encryption='0', hashing = '0', hashedFile = '', decryptionKey='0'):
		destination='abha808'
		file='HelloThisisaTest'
		output_dict = {'sender':sender,'destination':destination,'file':file, 'stamp':float(time.time()), 'filename':filename,'content_type':content_type, 'encryption':encryption, 'hashing':hashing, 'hash': hashedFile, 'decryptionKey':decryptionKey}
		data = json.dumps(output_dict) #data is a JSON object
		request = urllib2.Request('http://'+ ip + ':' + port + '/receiveFile' , data, {'Content-Type':'application/json'})
		response = urllib2.urlopen(request)
		print response.read()
	
	@cherrypy.expose
	def messageUserPage(self,destination = ''):
		Page = open('messaging.html').read().format(receiverUsername = destination)
	
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
			self.serverReportThreading(cherrypy.session['username'],cherrypy.session['hashedPassword'])
			raise cherrypy.HTTPRedirect('/')
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
			logoutResponse = urllib2.urlopen(logoutRequest)	
			logoutData = logoutResponse.read()
			print logoutData
			cherrypy.lib.sessions.expire()
		raise cherrypy.HTTPRedirect('/')
        
	def serverReportThreading(self,username,hashedPassword):
		thread.start_new_thread(self.serverReportTimer, (username,hashedPassword))

	def serverReportTimer(self,username,hashedPassword):
		beginTime=time.time()
		while True:
			time.sleep(30.0-((time.time()-beginTime)%30.0))#how many secs there are to the nearest 50 sec block of time, 50 minus that to figure out how long you have to sleep, the reason I do this is to account for variable execution times for self.authoriseUserLogin()
			self.authoriseUserLogin(username,hashedPassword)
	
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
		loginResponse = urllib2.urlopen(loginRequest)#Returns a response object for the requested URL
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
		self.getClientProfile()
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
			return ('0')
		except:
			return ('Error: Something went wrong')
		"""
		try:
			input_data = cherrypy.request.json
			print input_data
			return '0: '
			if(not('sender' in input_data))or(not('destination' in input_data))or(not('message' in input_data))or(not('stamp' in input_data)):
				return '1: Missing Compulsory Field'
			#if ('markdown' in input_data):
				#if (input_data['markdown'] == '1'):
					#message = markdown.markdown(input_data['message'])
				#else:
					#message = input_data['message'] 
			#else:
				#message = input_data['message'] 
			
			if('encryption' in input_data):
				if (input_data['encryption'] == '1')or(input_data['encryption'] == '0'):
					encryption = input_data['encryption']
				else:
					return '9: Encryption Standard Not Supported' 	
				
			print input_data
			return ('0: Success')
		except:
			return ('Error: Something went wrong')
		"""
	@cherrypy.expose
	#def sendMessage(self, sender='smoh944', destination='abha808', message='Hello This is a Test',ip='172.24.26.17',port='10001',markdown='0',encoding='0',encryption='0', hashing = '0', hashedMessage = '', decryptionKey='0'):
	def sendMessage(self, sender='smoh944', destination='smoh944', message='Hello This is a Test2',ip='127.0.0.1',port='10001',markdown='0',encoding='0',encryption='0', hashing = '0', hashedMessage = '', decryptionKey='0'):	
		if ((message == None)or(message == '')):
			pass
			
		output_dict = {'sender':sender,'destination':destination,'message':message, 'stamp':float(time.time()), 'markdown':markdown, 'encryption':encryption, 'hashing':hashing, 'hash': hashedMessage, 'decryptionKey':decryptionKey}
		data = json.dumps(output_dict) #data is a JSON object
		request = urllib2.Request('http://'+ ip + ':' + port + '/receiveMessage', data, {'Content-Type':'application/json'})
		response = urllib2.urlopen(request)
		print response.read()
		
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
