import nmap

def get_ports_and_services(host):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments='-Pn')  # Scan the host without pinging

    # Initialize an empty list to store ports, services, and their states
    ports_services_states = []

    # Iterate over all scanned hosts
    for host in nm.all_hosts():
        # Iterate over all open ports for the current host
        for port in nm[host]['tcp']:
            # Get the port number, service name, and port state
            port_number = port
            service = nm[host]['tcp'][port]['name']
            port_state = nm[host]['tcp'][port]['state']
            # Append the port number, service, and state to the list
            ports_services_states.append((port_number, service, port_state))

    return ports_services_states

if __name__ == "__main__":
    host = input("Enter the host IP address: ")  # Example host
    ports_services_states = get_ports_and_services(host)
    
    # Print extracted ports, services, and their states
    print("Port\tService\tState")
    for port, service, state in ports_services_states:
        print(f"{port}\t{service}\t{state}")
