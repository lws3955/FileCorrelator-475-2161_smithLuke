#!/usr/bin/python
import re
import sqlite3
import datetime
import sys
import mmap
import contextlib
import os
import argparse

from operator import itemgetter
from subprocess import PIPE, Popen
from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view





def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-i", "--imagefile", help="path to image file")
	parser.add_argument("-u", "--username", help="specific username used to correlate file times with. Defaults to all usernames", type=str, default="None")
	parser.add_argument("-t", "--timetype", help="specify which file timestamp to use: access(atime), modify(mtime), change(ctime), or creation(crtime) time. Defaults to modify time", type=str, choices=[ "mtime", "atime", "ctime", "crtime" ], default="mtime") 
	parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
	
	#TODO add output format options

	args = parser.parse_args()
	
	if( args.imagefile == None ):
		print( "Image file must be specified.\nUse \'FileCorrelator.py -h\' to show options.")
		sys.exit()

	#Check that file exists
	if( not os.path.isfile(str(args.imagefile)) ):
		print( "Image file specified does not exist.")
		sys.exit()
	else:
		image_file = args.imagefile

	
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
	conn.text_factory = str
	cursor = conn.cursor()
	cursor.execute('''CREATE TABLE userdata (recordID text, processID text, eventCode text, eventType text, time real, userName text, domainName text)''')
	cursor.execute('''CREATE TABLE filedata (fullpath text, partpath text, filename text, type text, size real, atime real, mtime real, ctime real, crtime real)''')
	conn.commit()



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

	
		
	dump = open(filetime_dump, 'r')
	for line in dump:
		line_arr = re.split('\|', str(line) )
		line_arr[1] = re.sub('vol\d+\/', '/', line_arr[1] )
		#prevent duplicate entries
		if( re.match('.*\(\$FILE_NAME\).*', line_arr[1] ) == None ):
			filename = re.split('\/', line_arr[1])[-1]
			partpath = ""
			for dir in re.split('\/', line_arr[1])[1:-1]:
				partpath = partpath + "/" + dir 
			type = ""
			if( re.match('.*d\/dr.*', line_arr[3] ) ):
				type = "dir"
			else:
				type = "file"
			cursor.execute('''INSERT into filedata (fullpath, partpath, filename, type, size, atime, mtime, ctime, crtime ) values ( ?, ?, ?, ?, ?, ?, ?, ?, ? )''', (str(line_arr[1]), str(partpath), str(filename), str(type), int(line_arr[6]) , int(line_arr[7]), int(line_arr[8]), int(line_arr[9]), int(line_arr[10]) ))		
	
	conn.commit()	
	dump.close()


	start_date = (datetime.datetime( 2016, 9, 1 ) - datetime.datetime(1970,1,1)).total_seconds()
        end_date = (datetime.datetime( 2016, 9, 10 ) - datetime.datetime(1970,1,1)).total_seconds()

	if( args.timetype == "crtime" ):
		filedata =  cursor.execute('''SELECT crtime, filename, partpath, type, size FROM filedata WHERE mtime BETWEEN ? AND ? ORDER BY crtime''', (start_date, end_date) ).fetchall()
	elif( args.timetype == "atime" ):
		filedata =  cursor.execute('''SELECT atime, filename, partpath, type, size FROM filedata WHERE atime BETWEEN ? AND ? ORDER BY atime''', (start_date, end_date) ).fetchall()
	elif( args.timetype == "ctime" ):
		 filedata =  cursor.execute('''SELECT ctime, filename, partpath, type, size FROM filedata WHERE ctime BETWEEN ? AND ? ORDER BY ctime''', (start_date, end_date) ).fetchall()
	else:
		 filedata =  cursor.execute('''SELECT mtime, filename, partpath, type, size FROM filedata WHERE mtime BETWEEN ? AND ? ORDER BY mtime''', (start_date, end_date) ).fetchall()	

	report = open("./report.txt", "w+")	
	
	for row in filedata:
		active_users = []
		results = cursor.execute('''SELECT time, eventCode, eventType, userName, domainName FROM userdata WHERE eventCode = "4624"  AND time BETWEEN ? AND ? ORDER BY time''', ( start_date, row[0]) ).fetchall()
		
		for test in results:
			more_results = cursor.execute('''SELECT time, eventCode, eventType, userName, domainName FROM userdata WHERE userName = ? AND ( eventCode = "4634" OR eventCode = "4647" ) AND time BETWEEN ? AND ? ORDER BY time''', ( test[3], test[0], row[0]) ).fetchall()
			if( len( more_results ) == 0 and test[3] not in active_users ):
				active_users.append(test[3])
		line = str(row) + ' ' + str(active_users) + '\n'
		report.write( line )
	report.close()

	conn.close()
	#event_dump.close()

		


if __name__ == "__main__":
    main()

