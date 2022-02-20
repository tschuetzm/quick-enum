# quick-enum
Quickly discover open ports of a target host, and enumerate those.  

<ins>The motivation behind this script:</ins>

Using nmap to perform a full port scan along with the option -A (enable OS and version detection, script scanning, and traceroute), can take a long time, especially when scanning a remote target via VPN, such as hosts in Offensive Security's OSCP/OSEP lab.

<ins>This script does the following:</ins>

1.  Discover any open ports of a target IP address, by scanning all 65535 TCP ports using masscan, and scan the top50 UDP ports using nmap. Save those found open ports in an array for an in-depth scan in the next step.
2.  Run nmap to a perform version detection and script scanning against the open ports from step one, along with operating system detection and traceroute.
3.  Convert the detailed nmap scan results into a CSV file, so that you can add this table to your pentesting report.

<ins>Requirements:</ins>

- nmap and masscan
- Get the nmaptocsv script from https://github.com/maaaaz/nmaptocsv, and store it in an directory that is in your $PATH, such as /usr/local/bin.
