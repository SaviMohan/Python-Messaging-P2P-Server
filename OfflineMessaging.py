""" OfflineMessaging.py

    COMPSYS302 - Software Design - Python Project
    Author: Savi Mohan (smoh944@auckland.ac.nz)
    Last Edited: 11/06/2017

    This program uses the CherryPy web server (from www.cherrypy.org).
	This file contains offline messaging functions called by MainFile.py
"""

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

def sendOfflineMessage(data,username,hashedPassword):
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
	
def sendOfflineFile(data,username,hashedPassword):
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