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
	realTimeData = sys.stdin.readline()
	return realTimeData

# The code that will run if the program is not required to run online:
def runOffline():
	# Open an output file to write to:
	writeToThis = open('scanReport.txt', 'w')
	for fileName in sorted(glob.glob('*.log'), key=numberFileSort):
			inputFile = open(fileName, 'r')
			fileLog = inputFile.read()
			inputFile.close()
			writeToThis.write("%s -->\n" % fileName)
	writeToThis.close()


# Sort the files in the directory before reading them into code:
numbers = re.compile(r'(\d+)')
def numberFileSort(val):
	parts = numbers.split(val)
	parts[1::2] = map(int, parts[1::2])
	return parts

##############################################################

# Main Code Execution Below:

realTimeFlag = checkIfRealTime()
OnlineOrOffline(realTimeFlag)