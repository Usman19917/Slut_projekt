import argparse
import os
import base64
import sys

try:
    import nmap
except ImportError:
    print("Fel: 'nmap' hittades inte. Installera med 'pip install python-nmap'")
    sys.exit(1)

try:
    from scapy.all import ARP, Ether, srp, sniff
except ImportError:
    print("Fel: 'scapy' hittades inte. Installera med 'pip install scapy'")
    sys.exit(1)

try:
    from cryptography.fernet import Fernet
except ImportError:
    print("Fel: 'cryptography' hittades inte. Installera med 'pip install cryptography'")
    sys.exit(1)

# Modul 1: Portskanning med Nmap
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

# Modul 2: Nätverksskanning med Scapy (ARP)
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
    
# Modul 3: Sniffing med Scapy
def packet_sniffer(interface, packet_count):
    def packet_callback(packet):
        print(packet.summary())  # Sammanfattning av varje paket

    try:
        print(f"Vänta medans det pågår {interface}... eller avbryt med ctrl+c")
        sniff(iface=interface, prn=packet_callback, count=packet_count, store=0)
    except Exception as e:
        print(f"Försök igen! {e}")

# Modul 4: Kryptering och dekryptering med Cryptography-Fernet
def generate_key():
    return Fernet.generate_key()

def encrypt_data(data, key):
    try:
        fernet = Fernet(key)
        encrypted = fernet.encrypt(data.encode())
        return encrypted.decode('utf-8')
    except Exception as e:
        print(f"Kryptering misslyckades! {e}")
        return None

def decrypt_data(encrypted_data, key):
    try:
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_data.encode())
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"Dykryptering misslyckades! {e}")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Program för penetrationstest")
    parser.add_argument("-n", "--network", type=str, help="Ange target för att skanna ex, (10.2.10.0/24)")
    parser.add_argument("-p", "--ports", type=str, help="Ange IP address för att skanna portar")
    parser.add_argument("-s", "--sniff", type=str, help="Välj för att sniffa")
    parser.add_argument("--count", type=int, default=0, help="Antal paket att sniffa")
    parser.add_argument("-e", "--encrypt", type=str, help="Ange för att kryptera information")
    parser.add_argument("-d", "--decrypt", type=str, help="Ange för att dekryptera information")
    parser.add_argument("-k", "--key", type=str, help="Säkerhetsnyckel för att kryptera eller dekryptera information")
    parser.add_argument("--g-k", action="store_true", help="Generera ny säkerhetsnyckel")
    args = parser.parse_args()

    # Nätverksskanning
    if args.network:
        print(f"Vänta medan skanning pågår {args.network}...")
        devices = network_scan(args.network)
        if devices:
            print("Found devices:")
            for device in devices:
                print(f"IP: {device['IP']}, MAC: {device['MAC']}")
        else:
            print("Något gick fel alt, Ingen enhet hittades.")

    # Portskanning
    if args.ports:
        print(f"Vänligen vänta pågår skanning {args.ports}...")
        port_results = scan_ports(args.ports)
        if port_results:
            for port, state in port_results:
                print(f"Port {port}: {state}")
        else:
            print("Inga öppna portar hittade!.")

    # Sniffning av paket
    if args.sniff:
        packet_sniffer(args.sniff, args.count)

    # Generera nyckel
    if args.g_k:
        key = generate_key()
        print(f"Säkerhetsnyckel: {key.decode('utf-8')}")

    # Kryptera data
    if args.encrypt and args.key:
        encrypted_data = encrypt_data(args.encrypt, args.key.encode())
        if encrypted_data:
            print(f"Encrypted Data: {encrypted_data}")
        else:
            print("Kryptering misslykades. Försök igen(Obs:Säkerhetsnyckel och inmatning)")

    # Dekryptera data
    if args.decrypt and args.key:
        decrypted_data = decrypt_data(args.decrypt, args.key.encode())
        if decrypted_data:
            print(f"Dekrypterad information: {decrypted_data}")
        else:
            print("Dekryptering misslykades! försök igen (Obs:Säkerhetsnyckel och inmatning)")
