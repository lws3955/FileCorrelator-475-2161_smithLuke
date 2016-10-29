#!/usr/bin/python
import re
import sqlite3
import datetime
import sys
import mmap
import contextlib
import os

from subprocess import PIPE, Popen
from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view





def main():
	args = sys.argv
	
	if( len(args) < 2 ):
		print( "Usage: FileCorrelator.py path/to/imagefile" )
		sys.exit()
	#Check that file exists
	if( not os.path.isfile(args[1]) ):
		print( "Image file specified does not exist.")
		sys.exit()
	else:
		image_file = args[1]
	
	#use mmls to find partitions in image file
	find_ntfs = Popen(['mmls', image_file ], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        partition_list  = re.split('\n', find_ntfs.communicate()[0] )
	
	ntfs_offset = 0
	found_windows = False
	


	#Check NTFS partitions for correct directory structure
        for line in partition_list:
                if( re.match('.*NTFS.*', line ) ):
                        ntfs_offset = re.split('\s+|\s',str(line) )[2]
			#use fls to check for correct NTFS partition
                        check_windows = Popen(['fls', '-o', ntfs_offset, image_file ], stdin=PIPE, stdout=PIPE, stderr=PIPE)
                        dir_list = re.split('\s', check_windows.communicate()[0])
			if( "Windows" in dir_list ):
				found_windows = True
				break
		

	if( not found_windows ):
		print("No valid Windows directory structure found in image file")
		sys.exit()
	
	print( ntfs_offset )
	found_log = False

	
	filetime_dump =  str(datetime.date.today()) + '_filetime.dump'
		
	dump = open( filetime_dump, 'w+')
	dump_filetimes = Popen(['tsk_gettimes', '-i', 'raw', image_file ], stdin=PIPE, stdout=PIPE, stderr=PIPE)
	for line in iter(dump_filetimes.stdout.readline, b''):
		dump.write(line)
	dump_filetimes.wait()
	dump.close()
	

	find_log = Popen(['grep', '/Windows/System32/winevt/Logs/Security.evtx', filetime_dump ], stdin=PIPE, stdout=PIPE, stderr=PIPE)
	logfile_inode =  re.split('\||\-', find_log.communicate()[0])[2]

	print( logfile_inode )

	logfile =  str(datetime.date.today()) + '_Security.evt'
       	log = open( logfile, 'w+')
        dump_logfile = Popen(['icat', '-f', 'ntfs', '-i', 'raw', '-o', ntfs_offset, '-r', image_file, logfile_inode ], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        for line in iter(dump_logfile.stdout.readline, b''):
                log.write(line)
        dump_logfile.wait()
        log.close()
        

	#Connect and build database
	database_name = str(datetime.date.today()) + '.db'
	conn = sqlite3.connect(database_name)
	cursor = conn.cursor()
	cursor.execute('''CREATE TABLE userdata (recordID text, processID text, eventCode text, eventType text, time real, userName text, domainName text)''')
	conn.commit()



	#event_dump = open('security_events.xml', 'w+')

	#open log file read event entries
	with open(logfile, 'r') as f:
		with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
			fh = FileHeader(buf, 0x0)
			
			for xml, record in evtx_file_xml_view(fh):
				test = re.split('\n', xml)
				#check for login event based on event code number
				if( re.match('.*(4624|4625).*', test[1] ) ):
					if( re.match('<Data Name=\"LogonType\">(2|3|7)</Data>', test[23] ) ):
						#event_dump.write(str(xml))
						recordID = re.search('(?<=>)\d+(?=<)', test[8] ).group(0)
						processID = re.search('(?<=ProcessID=\")\d+(?=\")', test[10] ).group(0)
						eventCode = re.search('(?<=>)\d+(?=<)', test[1] ).group(0)
						eventType = re.search('(?<=>)\d+(?=<)', test[23] ).group(0)
						time_array = re.split('\-|\s|\\:|\.', re.search('(?<=SystemTime=\")\d+\-\d+\-\d+ \d+\:\d+\:\S+(?=\")', test[7]).group(0) )
						time = (datetime.datetime( int(time_array[0]), int(time_array[1]), int(time_array[2]), int(time_array[3]), int(time_array[4]), int(time_array[5]) ) - datetime.datetime(1970,1,1)).total_seconds()
 
						userName =  re.search('(?<=TargetUserName\">).*(?=<)', test[20]).group(0)
						domainName =  re.search('(?<=TargetDomainName\">).*(?=<)', test[21]).group(0)
					  	#print( 'LOGON',test[1], test[7], test[20], test[21], test[23] )
						cursor.execute('''INSERT into userdata (recordID, processID, eventCode, eventType, time, userName, domainName) values ( ?, ?, ?, ?, ?, ?, ? )''', (recordID, processID, eventCode, eventType, time, userName, domainName))
				#check for logoff event based on event code number
				elif( re.match('.*(4634|4647).*', test[1] ) ):
					#event_dump.write(str(xml))
                                        #print( 'LOGOFF', test[1],test[7], test[16], test[17] )
					recordID = re.search('(?<=>)\d+(?=<)', test[8] ).group(0)
					processID = re.search('(?<=ProcessID=\")\d+(?=\")', test[10] ).group(0)
					eventCode = re.search('(?<=>)\d+(?=<)', test[1] ).group(0)
					eventType = "None"
					time_array = re.split('\-|\s|\\:|\.', re.search('(?<=SystemTime=\")\d+\-\d+\-\d+ \d+\:\d+\:\S+(?=\")', test[7]).group(0) )
					time = (datetime.datetime( int(time_array[0]), int(time_array[1]), int(time_array[2]), int(time_array[3]), int(time_array[4]), int(time_array[5]) ) - datetime.datetime(1970,1,1)).total_seconds()
					userName =  re.search('(?<=TargetUserName\">).*(?=<)', test[16]).group(0)
					domainName =  re.search('(?<=TargetDomainName\">).*(?=<)', test[17]).group(0)
                                       	cursor.execute('''INSERT into userdata (recordID, processID, eventCode, eventType, time, userName, domainName) values ( ?, ?, ?, ?, ?, ?, ? )''', (recordID, processID, eventCode, eventType, time, userName, domainName))

	conn.commit()


	#For testing only, confirm database has been built
	start_date = (datetime.datetime( 2016, 9, 1 ) - datetime.datetime(1970,1,1)).total_seconds()
	end_date = (datetime.datetime( 2016, 10, 1 ) - datetime.datetime(1970,1,1)).total_seconds()
	for row in cursor.execute('''SELECT * FROM userdata WHERE userName LIKE "L" AND time BETWEEN ? AND ? ORDER BY time''', (start_date, end_date,) ):
		print( row )

	conn.close()
	#event_dump.close()

		


if __name__ == "__main__":
    main()

