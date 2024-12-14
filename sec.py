from scapy.all import sniff
import argparse

def packet_sniffer(interface, packet_count):
    def packet_callback(packet):
        print(packet.summary())

    try:
        print(f"Vänta medans det pågår {interface}... eller avbryt med ctrl+c")
        sniff(iface=interface, prn=packet_callback, count=packet_count, store=0)
    except Exception as e:
        print(f"Försök igen! {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sniffning av paket")
    parser.add_argument("-s", "--sniff", type=str, help="Ange interface att sniffa på")
    parser.add_argument("--count", type=int, default=0, help="Antal paket att sniffa")
    args = parser.parse_args()

    if args.sniff:
        packet_sniffer(args.sniff, args.count)
    else:
        print("Ange ett interface med -s/--sniff")
