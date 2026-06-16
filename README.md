To use each scanner, you need to run "chmod +x requirements.sh" and then "./requirements.sh".
This is done to install all the tools needed for the scripts to run.

1) aggressive_scanner
(This scanner is written in Python and includes masscan (root), nmap, ffuf, gobuster, feroxbuster, nuclei, nikto, sqlmap, amass) 
     WARNING: THIS IS A VERY AGGRESSIVE SCANNER
2) stealth_scanner
(This scanner is written in Python using asyncio for stealth web directory enumeration. It automatically interacts with nmap via signatures to handle non-standard web ports like 8080 or 8443 dynamically)
    WARNING: RUN WITH SUDO FOR SYN SCANNING (-sS)
