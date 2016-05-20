#! /usr/bin/env python
# Project 3 : Network Scan Detection
# EECE 480F
# By: Jeffrey Grinberg
# Due May 22, 2016

import re
from optparse import OptionParser
import sys
import glob

# Function Declarations will appear below:

# Sort the files in the directory before reading them into code:
numbers = re.compile(r'(\d+)')
def numberFileSort(val):
	parts = numbers.split(val)
	parts[1::2] = map(int, parts[1::2])
	return parts


# Checking to see if the analytics are to be done real-time or with log files:
def checkIfRealTime():
	parser = OptionParser()
	parser.add_option("--online", action="store_true", dest="realTime")
	options,realTime = parser.parse_args()
	return options.realTime

# Decide if real time is needed to be run:
def OnlineOrOffline(var):
	# Accept stdin if realTime is true:
	if (var):
		runOnline()
	else:
		runOffline()

# The code that will run if the program is required to run in real-time
def runOnline():
	writeToThis = open('scanReport.txt', 'w')
	print 'Online: stdIn -->'
	writeToThis.write('Online: stdIn --> \n')
	# Since input is now a stream, I need to store it into a buffer.
	inStreamBuffer = []
	for line in sys.stdin:
		inStreamBuffer.append(line)

	getCorrectInfo(inStreamBuffer, writeToThis)
	writeToThis.close()


# The code that will run if the program is not required to run online:
def runOffline():
	# Open an output file to write to:
	writeToThis = open('scanReport.txt', 'w')
	for fileName in sorted(glob.glob('*.log'), key=numberFileSort):
		inputFile = open(fileName, 'r')
		fileLog = inputFile.read()
		inputFile.close()
		writeToThis.write("%s -->\n" % fileName)
		print "%s -->" % fileName

		# Identification of NMAP performed executed below:
		
		#Nmap flag initializers:
		nmapsS = 0
		nmapF = 0
		nmapsV = 0
		nmapO = 0
		nmapsn = 0

		# Go through every fileLog we have and dig inside to find all the
		# lines that have a typical identifier with NMAP scans:
		# 'ARP, Reply, #.#.#.#, length 28'
		# and look for the request that was made before it:
		logLine = fileLog.split('\n')
		getCorrectInfo(logLine, writeToThis)
	writeToThis.close()

def getCorrectInfo(logLine, writeToThis):
	for index, lineInfo in enumerate(logLine):
		# Set a counter that looks for every time an attacker IP address shows
		attackerIP = 0
		reverseItr = 0
		timeStamp = None
		
		if ('ARP, Reply ' in lineInfo and 'length 46' in lineInfo):
			# Go back and find the ARP, request that gave forced this reply:
			reverseItr = index
			reverseItrInfo = lineInfo
			#print "\nFound reply INDEX = %s" %index
			# Get the IP in the reply log and save it. Will need to compare to the requests to make sure
			# a match was found and the filter is looking properly for replies
			replyLine = lineInfo.split( )
			replyIP = replyLine[3]
			#print "reply IP is: %s" % replyIP
			while (True):
				if 'ARP, Request' in reverseItrInfo:
					if returnVictimIP(reverseItrInfo) == replyIP :
						break
				if reverseItr == 0:
					break
				else:
					reverseItr = reverseItr - 1
					reverseItrInfo = logLine[reverseItr]

			timeStampClean, victimIP, attackIP = returnRightData(reverseItrInfo)

			# Look for ICMP echo request with the right request made to the victim ip, this indicates
			# that this was nmap -O scan:
			writeNmapO = False
			portNumbersStored = []
			for nIndex, nmapInfo in enumerate(logLine):
				if nmapInfo.find(attackIP + ' > ' + victimIP + ': ICMP echo request,') != -1:
					writeNmapO = True
					nmapO = 1
					break
				# Count the number of ports to identify if it was a -sS or -F scan.
				elif (victimIP in nmapInfo) and ('>' in nmapInfo):
					nmapSplit = nmapInfo.split( )
					ipSplit = nmapSplit[2].split('.')
					if len(ipSplit) == 5:
						portNumber = ipSplit[4]
						if portNumber not in portNumbersStored:
							portNumbersStored.append(portNumber)
			print len(portNumbersStored)
			if len(portNumbersStored) < 150:
				writeToThis.write("		nmap -F from %s at %s\n" % (attackIP, timeStampClean))
				print "		nmap -F from %s at %s" % (attackIP, timeStampClean)
			elif writeNmapO == True:
				writeToThis.write("		nmap -O from %s at %s\n" % (attackIP, timeStampClean))
				print "		nmap -O from %s at %s" % (attackIP, timeStampClean)
			elif len(portNumbersStored) > 1000:
				writeToThis.write("		nmap -sS or -sV from %s at %s\n" % (attackIP, timeStampClean))
				print "		nmap -sS or -sV from %s at %s" % (attackIP, timeStampClean)
			else:
				writeToThis.write("		Scanned from %s at %s\n" % (attackIP, timeStampClean))
				print "		Scanned from %s at %s" % (attackIP, timeStampClean)


def returnRightData(reverseItrInfo):
	timeStampClean = None
	victimIP = None
	attackIP = None
	# The scanRequest is identified as: 
	# Timestamp 'ARP, Request who-has' VICTIM-IP 'tell' ATTACK-IP, 'length 46'
	# Store this information:
	if '(Broadcast)' in reverseItrInfo:
		request_split= reverseItrInfo.split( )
		timeStamp = request_split[0]
		timeStampClean = timeStamp[:-7]
		victimIP = request_split[4]
		attackIP = request_split[7][:-1]
	elif '(oui' in reverseItrInfo:
		request_split= reverseItrInfo.split( )
		timeStamp = request_split[0]
		timeStampClean = timeStamp[:-7]
		victimIP = request_split[4]
		attackIP = request_split[9][:-1]
	else:
		request_split= reverseItrInfo.split( )
		timeStamp = request_split[0]
		timeStampClean = timeStamp[:-7]
		victimIP = request_split[4]
		attackIP = request_split[6][:-1]
	return timeStampClean, victimIP, attackIP

# Function that checks if the Reply IP is found in the Request ARP
def returnVictimIP(reverseItrInfo):
	timeStampClean = None
	victimIP = None
	attackIP = None
	if '(Broadcast)' in reverseItrInfo:
		request_split= reverseItrInfo.split( )
		timeStamp = request_split[0]
		timeStampClean = timeStamp[:-7]
		victimIP = request_split[4]
		attackIP = request_split[7][:-1]
	elif '(oui' in reverseItrInfo:
		request_split= reverseItrInfo.split( )
		timeStamp = request_split[0]
		timeStampClean = timeStamp[:-7]
		victimIP = request_split[4]
		attackIP = request_split[9][:-1]
	else:
		request_split= reverseItrInfo.split( )
		timeStamp = request_split[0]
		timeStampClean = timeStamp[:-7]
		victimIP = request_split[4]
		attackIP = request_split[6][:-1]

	return victimIP

#def returnScanType():


##############################################################

# Main Code Execution Below:

realTimeFlag = checkIfRealTime()
OnlineOrOffline(realTimeFlag)