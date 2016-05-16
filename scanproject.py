#! /usr/bin/env python
# Project 3 : Network Scan Detection
# EECE 480F
# By: Jeffrey Grinberg
# Due May 22, 2016

import re
from optparse import OptionParser
import sys



# Function Declarations will appear below:

# Checking to see if the analytics are to be done real-time or with log files:
def checkIfRealTime():
	parser = OptionParser()
	parser.add_option("--online", action="store_true", dest="realTime")
	options,realTime = parser.parse_args()
	return options.realTime

# Accept stdin if realTime is true:
def runRealTime(var):
	if (var):
		realTimeData = sys.stdin.readline()
		print var
		return realTimeData
	else:
		print var









# Main Code Execution Below:
realTimeFlag = checkIfRealTime()
runRealTime(realTimeFlag)