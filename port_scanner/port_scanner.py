import nmap
import socket

# Initialize the nmap scanner
nmScan = nmap.PortScanner()

# Prompt the user for the IP address and port range
print('\nAll Hosts:')
print(nmScan.all_hosts())  # Show all active hosts
print('\nSpecify the IP address of the system to run the port scan:')
ip = input()

print('\nSpecify the range of ports to scan.')
print('\nEnter the starting port:')
start_port = input()
print('\nEnter the ending port:')
end_port = input()

# Scan all ports in the specified range
port_range = f"{start_port}-{end_port}"
nmScan.scan(ip, port_range)

# Output scan results
print('\n\n\nPort Scan Completed.\n\n\n')
print('\nScan Information:')
print(nmScan.scaninfo())

# Analyze and output open and filtered ports
open_ports_count = 0
filtered_ports_count = 0

for host in nmScan.all_hosts():
    print(f'Host: {host} ({nmScan[host].hostname()})')
    print(f'State: {nmScan[host].state()}')

    for protocol in nmScan[host].all_protocols():
        print('----------')
        print(f'Protocol: {protocol}')
        ports = sorted(nmScan[host][protocol].keys())  # Get sorted list of ports
        for port in ports:
            port_state = nmScan[host][protocol][port]['state']
            print(f'Port: {port}\tState: {port_state}')
            if port_state == 'open':
                open_ports_count += 1
            elif port_state == 'filtered':
                filtered_ports_count += 1

# Display results
print(f'\nNumber of Open Ports: {open_ports_count}')
print(f'\nNumber of Filtered Ports: {filtered_ports_count}')
print('\nEnter any key to exit.\n')
input()  # Wait for the user to press any key before exiting
