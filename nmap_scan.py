import nmap
import nmap_scan


def nmap_scan(host):
    nm = nmap.PortScanner()
    nm.scan(host, arguments='-sV -Pn -T4')  # Опции для сканирования

    with open('nmap_scan_results.txt', 'w') as file:
        for host in nm.all_hosts():
            file.write(f"Host : {host}\n")
            file.write(f"State : {nm[host].state()}\n")

            for proto in nm[host].all_protocols():
                file.write(f"Protocol : {proto}\n")

                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]['name']
                    file.write(f"Port : {port}\t State : {nm[host][proto][port]['state']}\t Service : {service}\n")


if __name__ == '__main__':
    host = input("Enter the host to scan: ")
    nmap_scan(host)
    print("Scan completed. Results saved in nmap_scan_results.txt")
