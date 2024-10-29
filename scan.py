import nmap 


scanner = nmap.PortScanner()

print("WELCOME, This is a Simple Nmap Automation Tool")
print("<-------------------------------------------->")

ipAddr = input ("Please enter the Ip Address: ")
print("The Ip you entered is", ipAddr)
type(ipAddr)

resp = input("""  \nPlease enter the type of scan you want to run
                1)SYN ACK SCAN
                2)UDP SCAN
                3)Comprehensive SCAN \n
                """)

print("You have selected option:", resp)

if resp == "1":
    try:
        print("Nmap Version is: ", scanner.nmap_version())
        scanner.scan(ipAddr, '1-1024', '-v -sS')
        
        if ipAddr in scanner.all_hosts():
            print(scanner.scaninfo())
            print("Ip Status:", scanner[ipAddr].state())
            print(scanner[ipAddr].all_protocols())
            open_ports = scanner[ipAddr].get('tcp', {}).keys()
            print("The open Ports:", open_ports)
        else:
            print(f"No hosts found for {ipAddr}.")
    except Exception as e:
        print(f"An error occurred: {e}")

elif resp == "2":
    try:
        print("Nmap Version is: ", scanner.nmap_version())
        scanner.scan(ipAddr, '1-1024', '-v -sU')
        
        if ipAddr in scanner.all_hosts():
            print(scanner.scaninfo())
            print("Ip Status:", scanner[ipAddr].state())
            print(scanner[ipAddr].all_protocols())
            open_ports = scanner[ipAddr].get('udp', {}).keys()
            print("The open Ports:", open_ports)
        else:
            print(f"No hosts found for {ipAddr}.")
    except Exception as e:
        print(f"An error occurred: {e}")


elif resp == "3":
    try:
        print("Nmap Version is: ", scanner.nmap_version())
        scanner.scan(ipAddr, '1-1024', '-v -sS -sV -sC -A -O')
        
        if ipAddr in scanner.all_hosts():
            print(scanner.scaninfo())
            print("Ip Status:", scanner[ipAddr].state())
            print(scanner[ipAddr].all_protocols())
            open_ports = scanner[ipAddr].get('tcp', {}).keys()
            print("The open Ports:", open_ports)
        else:
            print(f"No hosts found for {ipAddr}.")
    except Exception as e:
        print(f"An error occurred: {e}")

elif resp >= '4':
    print("Please Enter a Valid Option")