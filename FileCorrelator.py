#!/usr/bin/python
import re
import sqlite3
import datetime
import sys
import os.path
from imagemounter import ImageParser


#TODO specify log handler for ImageParser


def main():
	
	args = sys.argv

	#Check number of arguments passed to script
	if( len(args) < 2 ):
		print( "Usage: FileCorrelator.py path/to/imagefile" )
		sys.exit()
	#Check that file exists
	if( not os.path.isfile(args[1]) ):
		print( "Image file specified does not exist.")
		sys.exit()
	#Check that file has the DD extension
	if( not re.match('.*\.dd', args[1]) ):
		print( "Image file specified is not a dd image file")
		sys.exit()

	
	#Attempt to open image file, fail gracefully
	try:
		parser = ImageParser([args[1]])
		parser.init()
	except:
		print("Unable to open image file\nExiting..")
		sys.exit()
	
	#TODO verify image file contains Disk
	
	#TODO verfiy atleast one volume is ntfs
	
	

	
if __name__ == "__main__":
    main()
