""" dbFunctions.py

    COMPSYS302 - Software Design - Python Project
    Author: Savi Mohan (smoh944@auckland.ac.nz)
    Last Edited: 11/06/2017

    This program uses the CherryPy web server (from www.cherrypy.org).
	This file contains database functions called by MainFile.py
"""
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

def clearRateRequestTable():
	"""Clears the requestNumbers column in the RateRequest table to 0"""
	conn = sqlite3.connect(DB_USER_DATA)		
	# Once we have a Connection, we can create a Cursor object and call its execute() method to perform SQL commands
	c = conn.cursor()
	
	c.execute("UPDATE RequestRate SET requestsNumber = 0")
	
	conn.commit()
	conn.close()
	

def checkIfRateLimited(requestor=None):
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
	"""Creates a table to store user profile details. This table also allows us to support multiple user sessions on the same application"""
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

def getClientProfile(profile_username=''):
	"""Returns the profile data corresponding to an input username"""
	conn = sqlite3.connect(DB_USER_DATA)
	c = conn.cursor()
	c.execute('''SELECT * FROM ClientProfiles WHERE profile_username = ?''', (profile_username,))
	profileData = c.fetchone()
	conn.close()
	
	return profileData
	
def getUserData(username=''):
	"""Returns the user data corresponding to an input username"""
	conn = sqlite3.connect(DB_USER_DATA)
	c = conn.cursor()
	c.execute('''SELECT * FROM AllUsers WHERE username = ?''', (username,))
	userData = c.fetchone()
	conn.close()		
	return userData	


	

def createMessagesTable():
	"""Creates a table to store all messages"""
	conn = sqlite3.connect(DB_USER_DATA)
	
	# Once we have a Connection, we can create a Cursor object and call its execute() method to perform SQL commands
	c = conn.cursor()
	
	c.execute('''CREATE TABLE IF NOT EXISTS Messages (id INTEGER PRIMARY KEY, sender TEXT, destination TEXT, message TEXT, stamp REAL, markdown TEXT, isFile TEXT, fileLink TEXT, fileType TEXT, fileName TEXT)''')
	
	conn.commit()
	conn.close()

def getMessages(sender, destination):
	"""Returns all the messages stored in the database that correspond to the two input usernames"""
	conn = sqlite3.connect(DB_USER_DATA)
	c = conn.cursor()
	c.execute('''SELECT * FROM Messages WHERE ((sender=? AND destination=?)OR (sender=? AND destination=?)) order by stamp ''',(sender,destination,destination,sender))
	messages = c.fetchall()
	conn.commit()
	conn.close()		
	return messages
	
def getMessagesForOneUser(destination=''):
	"""Returns all the messages stored in the database which have a destination that corresponds to the input username """
	conn = sqlite3.connect(DB_USER_DATA)
	c = conn.cursor()
	c.execute('''SELECT * FROM Messages WHERE ( destination=?) order by stamp ''',(destination))
	messages = c.fetchall()
	conn.commit()
	conn.close()		
	
	return messages	
	
def insertIntoMessagesTable(sender = None, destination = None, message = None, stamp = None, markdown = '0',isFile = 'false', fileLink = None, fileType = None,fileName=None):	
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
	

	
def updateAllUsersTable(onlineUsersData, firstLogin = False):
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
				userData = getUserData(value['username'])	
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
	
def getAllUsersData():
	"""Returns every row in the AllUsers table"""
	conn = sqlite3.connect(DB_USER_DATA)
	c = conn.cursor()
	c.execute("SELECT * FROM AllUsers")
	usersData = c.fetchall()
	conn.commit()
	conn.close()
	return usersData