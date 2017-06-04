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

class MainApp(object):
			
	def getLocation(self,ip):
		if (('130.216.' in ip)or('10.103.' in ip)or('10.104.' in ip)):
			return '0'	#Uni Desktop
		elif(('172.23.' in ip)or('172.23.' in ip)):
			return '1'	#Uni WiFi
		else:
			return '2'	#Rest of World
	
	def getIP(self):
		internalIP = socket.gethostbyname(socket.getfqdn())	#internal ip address	
		externalIP = (urllib2.urlopen(urllib2.Request('http://ident.me'))).read().decode('utf8') #retrieves external ip	#encrypt?
		print internalIP
		print externalIP
		location = self.getLocation(internalIP)
		if ((location == '0')or(location == '1')):
			return str(internalIP)
		else:
			return str(externalIP)
	
	
	def createMessagesTable():
		conn = sqlite3.connect(DB_USER_DATA)
		
		# Database will have UTF-8 encoding
		conn.text_factory = str
		
		# Once we have a Connection, we can create a Cursor object and call its execute() method to perform SQL commands
		c = conn.cursor()
		
		c.execute('''CREATE TABLE IF NOT EXISTS Messages (id INTEGER PRIMARY KEY, sender TEXT, destination TEXT, message TEXT, stamp TEXT, markdown TEXT, encoding TEXT, encryption TEXT, hashing TEXT, hash TEXT, decryptionKey TEXT)''')
		
		conn.commit()
		conn.close()
		
	
	def createAllUsersTable():
		conn = sqlite3.connect(DB_USER_DATA)
		
		# Database will have UTF-8 encoding
		conn.text_factory = str
		
		# Once we have a Connection, we can create a Cursor object and call its execute() method to perform SQL commands
		c = conn.cursor()
		
		c.execute('''CREATE TABLE IF NOT EXISTS AllUsers (id INTEGER PRIMARY KEY, username TEXT, ip TEXT, location TEXT, lastLogin TEXT, port TEXT, status TEXT)''')
		
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
		conn = sqlite3.connect(DB_USER_DATA)
		c = conn.cursor()
		
		
		c.execute('''UPDATE AllUsers SET ip = ? , location = ?, lastLogin = ?, port = ? WHERE username = ?''', ('1', '1', '1', '1', 'smoh944'))
		
		conn.commit() # commit actions to the database
		conn.close()
		
	

	

	
	
	createAllUsersTable()
	createMessagesTable()
	populateAllUsersTable()
	

		
	
	webbrowser.open_new('http://%s:%d/' % ('localhost', listen_port)) # Opens web browser
	
    #CherryPy Configuration
	_cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }                 

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
		Page = '<form action="/signin" method="post" enctype="multipart/form-data">'
		Page += 'Username: <input type="text" name="username"/><br/>'
		Page += 'Password: <input type="password" name="password"/>'
		Page += '<input type="submit" value="Login"/></form>'
		return Page
    
	@cherrypy.expose
	def ping(self, sender=None):
		return '0'
	
	@cherrypy.expose
	def getProfile(self, profile_username):
		pass
	
	@cherrypy.expose
	@cherrypy.tools.json_in()
	def receiveFile(self):
		try:
			input_data = cherrypy.request.json
			print input_data
			return ('0: Success')
		except:
			return ('Error: Something went wrong')
		
	
	@cherrypy.expose
	def viewOnlineUsers(self):
		""" """
		try:
			Page = 'Users: '+cherrypy.session['onlineUsersData']+'<br/>'	
		except KeyError: #There is no online user list
			Page = 'No online user data available at this time<br/>'   
		    
		
		return Page
		
        
	# LOGGING IN AND OUT
	@cherrypy.expose
	def signin(self, username=None, password=None):
		"""Check their name and password and send them either to the main page, or back to the 			main login screen."""
		
		error = self.authoriseUserLogin(username,password)
		if (error == 0):
		    cherrypy.session['username'] = username;
		    raise cherrypy.HTTPRedirect('/')
		else:
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
        
	def authoriseUserLogin(self, username=None, password=None):
		passwordPlusSalt = password + SALT
		hashOfPasswordPlusSalt = hashlib.sha256(passwordPlusSalt).hexdigest()
		print hashOfPasswordPlusSalt

		#2cc4ba400f5105057f065f06ae9d758eb4388783038d738d6684666cb4297751
		#smoh944
		ip = self.getIP()
		location = self.getLocation(ip)
		
		loginRequest = urllib2.Request('http://cs302.pythonanywhere.com/report?username='+username+'&password='+hashOfPasswordPlusSalt+'&location='+location+'&ip='+ip+'&port='+str(listen_port)+'&enc=0')	#Object which represents the HTTP request we are making
		#loginRequest = urllib2.Request('http://cs302.pythonanywhere.com/report?username='+username+'&password='+hashOfPasswordPlusSalt+'&location=2&ip=118.92.154.45&port=10001&enc=0')
		loginResponse = urllib2.urlopen(loginRequest)#Returns a response object for the requested URL
		loginData = loginResponse.read() #The response is a file-like object, so .read() can be called on it
		
		#print loginData
		print username
		#print cherrypy.session.id
		#print password
		
		
		onlineUsersRequest = urllib2.Request('http://cs302.pythonanywhere.com/getList?username='+username+'&password='+hashOfPasswordPlusSalt+'&enc=0&json=1')
		onlineUsersResponse = urllib2.urlopen(onlineUsersRequest)
		onlineUsersData = onlineUsersResponse.read()
		
		print onlineUsersData
		cherrypy.session['onlineUsersData'] = onlineUsersData;
		#self.setupDatabase()
		#self.populateAllUsersTable()
		self.updateAllUsersTable([])
		#self.sendMessage()
		if (loginData[0] == "0") :
			cherrypy.session['hashedPassword'] = hashOfPasswordPlusSalt;
			return 0
		else:
		    return 1

	@cherrypy.expose
	@cherrypy.tools.json_in()
	def receiveMessage(self, encoding = 0):
		try:
			input_data = cherrypy.request.json
			print input_data
			return ('0: Success')
		except:
			return ('Error: Something went wrong')
		
	@cherrypy.expose
	def sendMessage(self, sender='smoh944', destination='ssit662', message='Hello This is a Test',ip='125.238.255.122',port='10008',markdown='0',encoding='0',encryption='0', hashing = '0', hashedMessage = '', decryptionKey='0'):
		output_dict = {'sender':sender,'destination':destination,'message':message, 'stamp':float(time.time()), 'markdown':markdown, 'encryption':encryption, 'hashing':hashing, 'hash': hashedMessage, 'decryptionKey':decryptionKey}
		data = json.dumps(output_dict) #data is a JSON object
		request = urllib2.Request('http://'+ ip + ':' + port + '/receiveMessage?encoding=' + encoding, data, {'Content-Type':'application/json'})
		response = urllib2.urlopen(request)
		print response.read()

          
def runMainApp():
	config = {
		 '/': {
		     'tools.sessions.on': True,#enabling sessions
		     'tools.staticdir.root': os.path.abspath(os.getcwd())#gets the absolute path to this folder
			
		 },
		 '/generator': {
		     'request.dispatch': cherrypy.dispatch.MethodDispatcher(),
		     'tools.response_headers.on': True,
		     'tools.response_headers.headers': [('Content-Type', 'text/plain')],
		 },
		 '/static': {	 
		     'tools.staticdir.on': True, #enabling a static directory which will serve static content to all of my webpages
		     'tools.staticdir.dir': './public'#static directory maps into public folder
		 }
	}
	#print os.path.abspath(os.getcwd())
    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all 		of them)
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
