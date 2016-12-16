Name:	 	    FileCorrelator

Author: Luke Smith

License: MIT 

Summary: 	  This tool will create a database time line correlating file modification with active user sessions.

Process:	  From disk image file correlate date/time information contained in file metadata with active user sessions. 
			      Process the information collected to then be passed to another tool for searching and visualization.
			
Disclaimer:	*Information gathered using this tool WILL NOT provide conclusive evidence that any particular user was responsible
             for any changes made to the file system.

Software Requirements:
1. Python 2.7 Website: www.python.org
2. Sleuthkit Utilities ( mmls, tsk_gettimes, icat, fls ) Website: www.sleuthkit.org
3. Python-evt Module (Used to parse Windows Log files) Website: www.williballenthin.com/evtx/

Input Requirements:
1. Raw disk image containing a complete Windows NTFS partition
2. Windows Security Event log must be present in the Windows NTFS partition

Usage: python FileCorrelator.py -i [imagefile] [-v/--verbose]

Output:
1. Plain text file containing output from the tsk_gettimes command
2. SQLite database containing one file metadata table and one logon/off event table
3. Plain text file containing correlated data in a JSON format