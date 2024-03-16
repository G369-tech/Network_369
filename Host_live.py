import nmap

def check_host_status(host):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments='-Pn')

    for host in nm.all_hosts():
        if nm[host]['status']['state'] == 'up':
            print(f"{host} is live.")
        else:
            print(f"{host} is not live.")

if __name__ == "__main__":
    ip = int(input("How many ip or hostname scan? "))
    for i in range(ip):
         host = input("Enter the host IP address or hostname: ")
         check_host_status(host)
