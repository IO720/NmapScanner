import nmap
import re

def is_valid_ip(ip):
    """ Validate IP address format. """
    pattern = re.compile(r"^(?:[0-255]{1,3}\.){3}[0-255]{1,3}$")
    return bool(pattern.match(ip))

def perform_scan(ip, scan_type):
    """ Perform the specified scan type. """
    try:
        print("Nmap Version is: ", scanner.nmap_version())
        scan_options = {
            '1': '-v -sS',
            '2': '-v -sU',
            '3': '-v -sS -sV -sC -A -O'
        }
        
        # Perform scan
        scanner.scan(ip, '1-1024', scan_options[scan_type])
        
        if ip in scanner.all_hosts():
            print(scanner.scaninfo())
            print("IP Status:", scanner[ip].state())
            print("Protocols:", scanner[ip].all_protocols())
            open_ports = scanner[ip].get('tcp', {}).keys() or scanner[ip].get('udp', {}).keys()
            print("Open Ports:", open_ports)
        else:
            print(f"No hosts found for {ip}.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Main code
scanner = nmap.PortScanner()

# Logo Display
logo = """
_____    ____             ______   ___     ___  
 |_   _|  / __ \           |____  | |__ \   / _ \ 
   | |   | |  | |              / /     ) | | | | |
   | |   | |  | |             / /     / /  | | | |
  _| |_  | |__| |            / /     / /_  | |_| |
 |_____|  \____/            /_/     |____|  \___/ 
                   ______                         
                  |______|                        

"""
print(logo)

print("<-------------------------------------------->")

ipAddr = input("Please enter the IP Address: ")
if not is_valid_ip(ipAddr):
    print("Invalid IP address format. Please try again.")
else:
    print("The IP you entered is", ipAddr)
    
    resp = input("""\nPlease enter the type of scan you want to run
                    1) SYN ACK SCAN
                    2) UDP SCAN
                    3) Comprehensive SCAN \n
                    """)

    print("You have selected option:", resp)

    if resp in ['1', '2', '3']:
        perform_scan(ipAddr, resp)
    else:
        print("Please enter a valid option.")
