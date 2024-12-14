import nmap
from scapy.all import ARP, Ether, srp
import argparse

def scan_ports(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, '1-1024')
        results = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    state = nm[host][proto][port]['state']
                    results.append((port, state))
        return results
    except Exception as e:
        print(f"Misslyckades att skanna: {e}")
        return None

def network_scan(target_range):
    try:
        arp = ARP(pdst=target_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=3, verbose=0)[0]
        devices = []
        for sent, received in result:
            devices.append({'IP': received.psrc, 'MAC': received.hwsrc})
        return devices
    except Exception as e:
        print(f"Något gick fel, försök igen {e}")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nätverksskanning eller portskanning")
    parser.add_argument("-n", "--network", type=str, help="Ange target för att skanna ex, (10.2.10.0/24)")
    parser.add_argument("-p", "--ports", type=str, help="Ange IP address för att skanna portar")
    args = parser.parse_args()

    if args.network:
        print(f"Vänta medan skanning pågår {args.network}...")
        devices = network_scan(args.network)
        if devices:
            print("Hittade enheter:")
            for device in devices:
                print(f"IP: {device['IP']}, MAC: {device['MAC']}")
        else:
            print("Något gick fel alt, Ingen enhet hittades.")
    if args.ports:
        print(f"Vänligen vänta pågår skanning {args.ports}...")
        port_results = scan_ports(args.ports)
        if port_results:
            for port, state in port_results:
                print(f"Port {port}: {state}")
        else:
            print("Inga öppna portar hittade!.")
