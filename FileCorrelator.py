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
	#initialize and set expected parameters
	parser = argparse.ArgumentParser()
	parser.add_argument("-i", "--imagefile", help="path to image file")
	parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
	

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
	if( args.verbose ): print("Executing mmls on image file: " + image_file )
	find_ntfs = Popen(['mmls', image_file ], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        partition_list  = re.split('\n', find_ntfs.communicate()[0] )
	if( args.verbose ): print("Finished successfully" )

	ntfs_offset = 0
	found_windows = False


	#Check NTFS partitions for correct directory structure
	if( args.verbose ): print("Finding NTFS partiton with windows")
        for line in partition_list:
                if( re.match('.*NTFS.*', line ) ):
                        ntfs_offset = re.split('\s+|\s',str(line) )[2]
			#use fls to check for correct NTFS partition
                        check_windows = Popen(['fls', '-o', ntfs_offset, image_file ], stdin=PIPE, stdout=PIPE, stderr=PIPE)
                        dir_list = re.split('\s', check_windows.communicate()[0])
			if( "Windows" in dir_list ):
				found_windows = True
				if( args.verbose ): print("Sucessfully found NTFS Windows")
				break
		

	if( not found_windows ):
		print("No valid Windows directory structure found in image file")
		sys.exit()
	
	found_log = False
	#recover file metadata from image and store in .dump file
	filetime_dump =  str(datetime.date.today()) + '_filetime.dump'
	dump = open( filetime_dump, 'w+')
	if( args.verbose ): print("Executing tsk_gettimes on NTFS partition")
	dump_filetimes = Popen(['tsk_gettimes', '-i', 'raw', image_file ], stdin=PIPE, stdout=PIPE, stderr=PIPE)
	for line in iter(dump_filetimes.stdout.readline, b''):
		dump.write(line)
	dump_filetimes.wait()
	if( args.verbose ): print("Finished sucessfully")
	dump.close()
	
	#retrive inode value for Windows Security Log file
	if( args.verbose ): print("Locating inode value of Security.evtx file")
	find_log = Popen(['grep', '/Windows/System32/winevt/Logs/Security.evtx', filetime_dump ], stdin=PIPE, stdout=PIPE, stderr=PIPE)
	logfile_inode =  re.split('\||\-', find_log.communicate()[0])[2]
	if( args.verbose ): print("Inode value found sucessfully")

	#recover Windows Security Log file
	logfile =  str(datetime.date.today()) + '_Security.evt'
       	log = open( logfile, 'w+')
	if( args.verbose ): print("Executing icat to recover Security.evtx file")
        dump_logfile = Popen(['icat', '-f', 'ntfs', '-i', 'raw', '-o', ntfs_offset, '-r', image_file, logfile_inode ], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        for line in iter(dump_logfile.stdout.readline, b''):
                log.write(line)
        dump_logfile.wait()
        log.close()
	if( args.verbose ): print("Finished sucessfully")
      
	
	#Connect and build sqlite database
	if( args.verbose ): print("Creating database for recovered data")
	database_name = str(datetime.date.today()) + '.db'
	conn = sqlite3.connect(database_name)
	conn.text_factory = str
	cursor = conn.cursor()
	if( args.verbose ): print("Creating table for Windows Security Log data")
	cursor.execute('''CREATE TABLE userdata (recordID text, processID text, eventCode text, eventType text, time real, userName text, domainName text)''')
	if( args.verbose ): print("Creating table for filesystem metadata")
	cursor.execute('''CREATE TABLE filedata (fullpath text, partpath text, filename text, type text, size real, atime real, mtime real, ctime real, crtime real)''')
	conn.commit()

	#open log file read event entries
	if( args.verbose ): print("Begin populating table with Windows Security Log data")
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
						cursor.execute('''INSERT into userdata (recordID, processID, eventCode, eventType, time, userName, domainName) values ( ?, ?, ?, ?, ?, ?, ? )''', (recordID, processID, eventCode, eventType, time, userName, domainName))
				#check for logoff event based on event code number
				elif( re.match('.*(4634|4647).*', test[1] ) ):
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
	if( args.verbose ): print("Sucessfully populated table with Windows Security Log data")
	
	#Read filesystem metadata from file and store into database	
	if( args.verbose ): print("Begin populating table with filesystem metadata")
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
	if( args.verbose ): print("Sucessfully populated table with filesystem metadata")
	
	#retireve filesystem metadata
	filedata =  cursor.execute('''SELECT mtime, atime, ctime, crtime, filename, partpath, fullpath, type, size FROM filedata''').fetchall()	

	report = open("./report_json.txt", "w+")	
	report.write("{\n\"FileCorrelator\": {\n")

	user_results = cursor.execute('''SELECT userName FROM userdata''').fetchall()
	username_list = []
	for result in user_results:
		if( result[0] not in username_list ): username_list.append(result[0])
		

	for row in filedata:
		mtime_au = []
		atime_au = []
		ctime_au = []
		crtime_au = []
		
		for username in username_list:
			#check for active session for mtime
			logon_results = cursor.execute('''SELECT time, eventCode, eventType, userName, domainName FROM userdata WHERE eventCode = "4624" AND userName = ? AND time < ? ORDER BY time''', (username, row[0]) ).fetchall()
                        if( len( logon_results ) != 0 ):
                                logoff_results = cursor.execute('''SELECT time, eventCode, eventType, userName, domainName FROM userdata WHERE userName = ? AND ( eventCode = "4634" OR eventCode = "4647" ) AND time BETWEEN ? AND ? ORDER BY time''', ( username, logon_results[-1][0], row[0]) ).fetchall()
                                if( len(logoff_results ) == 0 ): mtime_au.append(username)


			#check for active session for atime
			logon_results = cursor.execute('''SELECT time, eventCode, eventType, userName, domainName FROM userdata WHERE eventCode = "4624" AND userName = ? AND time < ? ORDER BY time''', (username, row[1]) ).fetchall()
                        if( len( logon_results ) != 0 ):
                                logoff_results = cursor.execute('''SELECT time, eventCode, eventType, userName, domainName FROM userdata WHERE userName = ? AND ( eventCode = "4634" OR eventCode = "4647" ) AND time BETWEEN ? AND ? ORDER BY time''', ( username, logon_results[-1][0], row[1]) ).fetchall()
                                if( len(logoff_results ) == 0 ): atime_au.append(username)
			
			#check for active session for ctime
			logon_results = cursor.execute('''SELECT time, eventCode, eventType, userName, domainName FROM userdata WHERE eventCode = "4624" AND userName = ? AND time < ? ORDER BY time''', (username, row[2]) ).fetchall()
                        if( len( logon_results ) != 0 ):
                                logoff_results = cursor.execute('''SELECT time, eventCode, eventType, userName, domainName FROM userdata WHERE userName = ? AND ( eventCode = "4634" OR eventCode = "4647" ) AND time BETWEEN ? AND ? ORDER BY time''', ( username, logon_results[-1][0], row[2]) ).fetchall()
                                if( len(logoff_results ) == 0 ): ctime_au.append(username)

			#check for active session for crtime
			logon_results = cursor.execute('''SELECT time, eventCode, eventType, userName, domainName FROM userdata WHERE eventCode = "4624" AND userName = ? AND time < ? ORDER BY time''', (username, row[3]) ).fetchall()
			if( len( logon_results ) != 0 ):
				logoff_results = cursor.execute('''SELECT time, eventCode, eventType, userName, domainName FROM userdata WHERE userName = ? AND ( eventCode = "4634" OR eventCode = "4647" ) AND time BETWEEN ? AND ? ORDER BY time''', ( username, logon_results[-1][0], row[3]) ).fetchall()
				if( len(logoff_results ) == 0 ): crtime_au.append(username)
		

		#Add None, if no user sessions were active
		if( len ( mtime_au ) == 0 ): mtime_au.append("None")
		if( len ( atime_au ) == 0 ): atime_au.append("None")
		if( len ( ctime_au ) == 0 ): ctime_au.append("None")
		if( len ( crtime_au ) == 0 ): crtime_au.append("None")
		
		#write FileEntry JSON object to file
		report.write("\t\t\"FileEntry\": {\n")
		report.write("\t\t\t\"fullpath\": \"" + str( row[6] ) + "\",\n")
		report.write("\t\t\t\"filename\": \"" + str( row[4] ) + "\",\n")
		report.write("\t\t\t\"partpath\": \"" + str( row[5] ) + "\",\n")
		report.write("\t\t\t\"type\": \"" + str( row[7] ) + "\",\n")
		report.write("\t\t\t\"size\": " + str( row[8] ) + ",\n")

		report.write("\t\t\t\"mtime\": {\n")
		report.write("\t\t\t\t\"time\": " + str( row[0] ) + ",\n")
		report.write("\t\t\t\t\"usersession\": " + str( mtime_au )+ "\n") 
		report.write("\t\t\t},\n")

		report.write("\t\t\t\"atime\": {\n")
                report.write("\t\t\t\t\"time\": " + str( row[1] ) + ",\n")
                report.write("\t\t\t\t\"usersession\": " + str( atime_au )+ "\n")
                report.write("\t\t\t},\n")


		report.write("\t\t\t\"ctime\": {\n")
                report.write("\t\t\t\t\"time\": " + str( row[2] ) + ",\n")
                report.write("\t\t\t\t\"usersession\": " + str( ctime_au )+ "\n")
                report.write("\t\t\t},\n")

		report.write("\t\t\t\"crtime\": {\n")
                report.write("\t\t\t\t\"time\": " + str( row[3] ) + ",\n")
                report.write("\t\t\t\t\"usersession\": " + str( crtime_au )+ "\n")
                report.write("\t\t\t}\n")

		report.write("\t\t},\n")


	report.write("\t}\n}\n")
	report.close()

	conn.close()


if __name__ == "__main__":
    main()

