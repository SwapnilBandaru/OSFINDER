Requriments: 
	1.Nmap should be installed in your system to run the Script.
	2. Java  should be installed in your system to execute the Script.
The program then uses the subnet in an Nmap command (`nmap -p 445 --script smb-os-discovery ###.###.###.0/24`), which is also run from the windows command line (CMD)
===========================================Instructions
===============
====================================================
1. Install Nmap for Windows (http://nmap.org/download.html#windows)
2. Download the OSFinder File. 
3. Run the OSFinder Java file in Command Prompt.
===========================================How OSFinder Runs============================================================
>OSFinder uses Nmap to find the operating system, computer name, hardware, and the MAC Address of computers on a subnet.This Parses the output of the Nmap output and  this data is outputted in the form of a CSV that is generated in the same directory(Same Folder) that OSFinder is run in.
> OSFinder currently looks for operating systems of WindowsXP,Windows 7,Windows 8,Windows 10,Windows 11.
>The program uses the ip address range provided and searches all the subnets of the IP Address provided as input.
> This Returns all the systems of specified os  in the range of IPAddress provided along with its System name ,MAC Address,Hardware details,Computer Name and IP Address.

======================================Steps to run the OSFinder============================================================
1) Open the Command Prompt from the start menu or from the run.
2) Type the command to change the directory to the OSFinder Folder:  cd (path of your Osfinder Folder)
3) To excute the Script run:" java OSfinder " . and enter the ip Address.
4) This command Excutes the File and Generates the csv File.
5) There are other Arguments that we can provide while executing . "-eo" argument displays output in Command Prompt.
6) The Default Argument searches for the Windows XP operating Systems.For the other  Operating Systems,we need to specify such as "-os7" or "os8"
	Example: java OSFinder -os7 (This returns information of all the Windows  7 Systems)
		java OSFinder -eo -os8(This returns information of all the Windows  8 Systems and Output in CMD)




Commands(Arguments):

		"-os7" = returns all system information of windows 7
		"-os8" = returns all system information of windows 8
		"-os10"= returns all system information of windows 10
		"-os11"=returns all system information of windows 11
		"-osunix"= returns all the unix system info
		"osall"=returns all the systems information(all os)

