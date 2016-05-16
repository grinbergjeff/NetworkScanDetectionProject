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
def runRealTime(var):
	# Open an output file to write to:
	writeToThis = open('scanReport.txt', 'w')

	# Accept stdin if realTime is true:
	if (var):
		realTimeData = sys.stdin.readline()
		return realTimeData
	else:
		for fileName in sorted(glob.glob('*.log'), key=numberFileSort):
			# For each file, I need to read it in and output the file name:
			inputFile = open(fileName, 'r')
			fileLog = inputFile.read()
			inputFile.close()
			#print fileName
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
runRealTime(realTimeFlag)