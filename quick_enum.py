#!/usr/bin/python3
import datetime, subprocess, os, time, sys 

if os.geteuid() != 0:
    exit("You need to have root privileges to run this script.\nExiting.")

if len(sys.argv) != 2:
    print("Usage: ./quick_enum.py <Target IP>")
    sys.exit(0)

ip_address = str(sys.argv[1])

global tports
global uports
global timestr
tports = []
uports = []
timestr = time.strftime("%Y%m%d-%H%M%S")

# Change this value to tun0 if connected to an OffSec OpenVPN
network_interface = "eth0"


def tcpscan(ip_address):

	filename = "masscan_results_%s_%s.txt" % (ip_address, timestr)
	tcptest = "masscan --open --interactive -p1-65535 --rate=1000 --adapter %s -oG %s %s" % (network_interface, filename, ip_address)
	calltcpscan = subprocess.Popen(tcptest, stdout=subprocess.PIPE, shell=True)

	#  wait for the subprocess to complete
	calltcpscan.wait()

	print("\t[!] Masscan finished for all 65,535 TCP ports, timestamped: " + str(datetime.datetime.fromtimestamp(time.time()).strftime("%H:%M:%S")))

	# If masscan does not find any open ports, its output file is empty.
	if (os.stat(filename).st_size == 0):
		print("\t[!] There were no open TCP ports..." + "\n")

	with open(filename) as fp:
		for line in fp:
		
	    	# grab only the lines we're interested in
			if line.startswith('Timestamp'):
				# split each element of a line and put it into an array 'parts'
				parts = line.strip().split()
				port = parts[6]
				# split it by '/' and grab the first element
				port = port.split('/')[0]
				
				tports.append(port)
	
	if tports:			
		print("\tFound TCP port(s): " + ",".join(map(str, tports)))


def udpscan(ip_address):

	filename = "nmap_udp_top50_scan_%s_%s.txt" % (ip_address, timestr)
	udptest= "nmap -sU -T4 --top-ports 50 --open -e %s -oN %s %s" % (network_interface,filename, ip_address)
	calludpscan = subprocess.Popen(udptest, stdout=subprocess.PIPE, shell=True)
	
	#  wait for the subprocess to complete
	calludpscan.wait()

	print("\t[!] Nmap scan finished for its Top 50 UDP ports, timestamped: " + str(datetime.datetime.fromtimestamp(time.time()).strftime("%H:%M:%S")))

	with open(filename) as fp:
		for line in fp:
			
	    	# grab only the lines we're interested in
			if ('/udp' in line and not 'filtered' in line):
				# split each element of a line and put it into an array 'parts'
				parts = line.strip().split()
				port = parts[0]
				# split it by '/' and grab the first element
				port = port.split('/')[0]

				uports.append(port)

	if uports:
		print("\tFound UDP port(s): " + ",".join(map(str, uports)))
	else:
		print("\t[!] There were no open UDP ports..." + "\n")

			


def nmap_enumeration_scan(ip_address, tports, uports):

	# Port 1 is added as the OS detected requires one closed port, and TCP/1 is closed in most cases ;-)
	run_nmap = "nmap -sT -sU -pT:1," + ",".join(map(str, tports)) + ",U:" + ",".join(map(str, uports)) + " -e %s -Pn -A --script vuln -oN nmap_enumeration_scan_%s_%s.txt %s" % (network_interface, ip_address, timestr, ip_address)
 	
	print("\nStarting nmap service version, default and vulnerabilities scripts, OS detection and traceroute scans against target %s now:" % ip_address)
    
  
	callnmapscan = subprocess.Popen(run_nmap, stdout=subprocess.PIPE, shell=True)

	# show output of the nmap scanning progress
	while True:
		output = callnmapscan.stdout.readline()
		if callnmapscan.poll() is not None:
			break
		if output:
			print(output.strip())
	rc = callnmapscan.poll()
		
	#  wait for the subprocess to complete
	callnmapscan.wait()


def nmap_to_csv():

	print("Converting nmap output to CSV: nmap_enumeration_scan_%s.csv" % ip_address)
	clean_up_file = "sed '/^|/d' nmap_enumeration_scan_%s_%s.txt > /dev/shm/%s.txt" % (ip_address, timestr, ip_address)
	call_clean_up_file = subprocess.Popen(clean_up_file, stdout=subprocess.PIPE, shell=True)
	call_clean_up_file.wait()


	nmap_to_csv = "nmaptocsv -i /dev/shm/%s.txt -f ip-fqdn-port-protocol-service-version-os -d ',' > nmap_enumeration_scan_%s_%s.csv" % (ip_address, ip_address, timestr)
	call_nmap_to_csv = subprocess.Popen(nmap_to_csv, stdout=subprocess.PIPE, shell=True)
	call_nmap_to_csv.wait()
        
	print("Done!")


def main():

	print("[!] Running initial TCP/UDP fingerprinting on %s using interface %s [*]" % (ip_address, network_interface))
	print("\t[!] Starting scans on " + str(datetime.datetime.fromtimestamp(time.time()).strftime("%A %B %d, %Y at %H:%M:%S")) )

	tcpscan(ip_address)
	udpscan(ip_address)

	if (not tports and not uports):
		print("Skipping nmap enumeration scan, as no open ports were discovered.")
	else:
		nmap_enumeration_scan(ip_address, tports, uports)

		# check if nmaptocsv is installed
		is_nmaptocsv_installed = subprocess.Popen("which nmaptocsv", stdout=subprocess.PIPE, shell=True)
		is_nmaptocsv_installed.wait()
		if (is_nmaptocsv_installed.returncode == 0):
			nmap_to_csv()
		else:
			print("nmaptocsv was not found. Skipping.\nEnsure that it is installed and its installation directory is present in $PATH.\nSource: https://github.com/maaaaz/nmaptocsv")



if __name__ == "__main__":
    main()
