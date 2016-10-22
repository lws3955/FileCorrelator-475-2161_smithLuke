#!/usr/bin/python
import re
import sqlite3
import datetime
import sys
import mmap
import contextlib

from os import path, mkdir
from subprocess import PIPE, Popen
from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view





def main():
	
	mount_path = '/mnt/test'
	log_path = '/mnt/test/Windows/System32/winevt/Logs/Security.evtx'	
	found_log = False

	#Connect and build database
	database_name = str(datetime.date.today()) + '.db'
	conn = sqlite3.connect(database_name)
	cursor = conn.cursor()
	cursor.execute('''CREATE TABLE userdata (recordID text, processID text, eventCode text, eventType text, time real, userName text, domainName text)''')
	conn.commit()

	#Use fdisk to find all available partitions  
	proc1 = Popen(['fdisk', '-l'], stdin=PIPE, stdout=PIPE, stderr=PIPE)
	partition_list  = re.split('\n', proc1.communicate()[0] )

	#Check NTFS partitions for correct directory structure
	for line in partition_list:
		if( re.match('.*NTFS.*', line ) ):
			ntfs_path = re.split('\s',str(line) )[0]
			if( not path.exists(mount_path) ):
				mkdir( mount_path )
			proc2 = Popen(['mount', '-t', 'ntfs', '-r', ntfs_path, mount_path ], stdin=PIPE, stdout=PIPE, stderr=PIPE)	
			proc2.communicate()
			if( proc2.returncode == 0 and path.exists( log_path ) == True ):
				found_log = True
				break

	#Quit if cannot find log file
	if( not found_log ):
		print( "Unable to find log file in NTFS partitions" )
		sys.exit()

	#event_dump = open('security_events.xml', 'w+')

	#open log file read event entries
	with open(log_path, 'r') as f:
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

