import nmap
import nmap_scan


def nmap_scan(host):
    nm = nmap.PortScanner()
    nm.scan(host, '22-80')
    for host in nm.all_hosts():
        print(f'Host: {host} ({nm[host].hostname()})')
        print(f'State: {nm[host].state()}')
        for proto in nm[host].all_protocols():
            print(f'Protocol: {proto}')
            lport = nm[host][proto].keys()
            for port in lport:
                print(f'Port: {port}\tState: {nm[host][proto][port]["state"]}')

if __name__ == "__main__":
    host = input("Enter the host to scan: ")
    nmap_scan(host)
