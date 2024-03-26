from scapy.all import *
from colorama import Fore

red = Fore.RED
yellow = Fore.YELLOW
green = Fore.GREEN
blue = Fore.BLUE
reset = Fore.RESET

counts = {}
ports = {21: "FTP", 22: "SSH", 23: "Telnet", 161: "SNMP", 162: "SNMP Trap", 520: "RIP", 25: "SMTP", 53: "DNS"}
alerted = {}
limit = 20
iface = ""

def update(port):
    name = ports.get(port, "Unknown")
    counts[name] = counts.get(name, 0) + 1
    if counts[name] > limit and name in ports.values() and not alerted.get(name, False):
        print(f"{red}[Alert]: Packet count on port {name} has exceeded",limit)
        alerted[name] = True

def update_icmp():
    counts["ICMP"] = counts.get("ICMP", 0) + 1
    if counts["ICMP"] > limit and not alerted.get("ICMP", False):
        print(f"{red}[Alert]: ICMP packet count has exceeded",limit)
        alerted["ICMP"] = True

def update_syn():
    counts["SYN"] = counts.get("SYN", 0) + 1
    if counts["SYN"] > limit and not alerted.get("SYN", False):
        print(f"{red}[Alert]: SYN packet count has exceeded",limit)
        alerted["SYN"] = True

def store(packet):
    if 'TCP' in packet:
        update(packet['TCP'].dport)
        if packet['TCP'].flags & 2:
            update_syn()
    if 'UDP' in packet:
        update(packet['UDP'].dport)
    if 'ICMP' in packet:
        update_icmp()

def sniff_packets(count=None):
    if count is not None:
        sniff(iface=iface, prn=store, store=0, count=count)
    else:
        sniff(iface=iface, prn=store, store=0)

def display_counts():
    print(f"\n{yellow}Packet Counts:")
    for name, count in counts.items():
        print(f"{green}{name}: {blue}{count} packets")

def extractor(cp):
    packet_info = {}
    try:
        if 'IP' in cp:
            packet_info['"Destination IP"'] = cp['IP'].dst
            packet_info['"Source IP"'] = cp['IP'].src
            packet_info['"Protocol"'] = cp['IP'].proto
            packet_info['"TTL"'] = cp['IP'].ttl

        if 'TCP' in cp:
            packet_info['"TCP Source Port"'] = cp['TCP'].sport
            packet_info['"TCP Destination Port"'] = cp['TCP'].dport
            packet_info['"TCP Flags"'] = cp['TCP'].flags
            packet_info['"TCP Acknowledgment Number"'] = cp['TCP'].ack
            packet_info['"TCP Sequence Number"'] = cp['TCP'].seq
            packet_info['"TCP Window"'] = cp['TCP'].window
            packet_info['"TCP Options"'] = cp['TCP'].options

        if 'UDP' in cp:
            packet_info['"UDP Source Port"'] = cp['UDP'].sport
            packet_info['"UDP Destination Port"'] = cp['UDP'].dport

        if 'ICMP' in cp:
            packet_info['"ICMP Type"'] = cp['ICMP'].type
            packet_info['"ICMP Code"'] = cp['ICMP'].code

        if 'DNS' in cp:
            if cp.haslayer('DNS') and cp['DNS'].qd:
                packet_info['"DNS ID"'] = cp['DNS'].id
                packet_info['"DNS QR"'] = cp['DNS'].qr
                packet_info['"DNS OpCode"'] = cp['DNS'].opcode
                packet_info['"DNS Response Code"'] = cp['DNS'].rcode
                packet_info['"DNS Question"'] = cp['DNS'].qd.qname
                packet_info['"DNS Answer"'] = cp['DNS'].an
        
        if 'Ether' in cp:
            packet_info['Ethernet'] = {
                'source': cp['Ether'].src,
                'destination': cp['Ether'].dst,
                'type': cp['Ether'].type
            }
        
        print(f"{yellow}[~]{green}{packet_info}")
        print() 

    except Exception as e:
        print("{yellow}ERROR: {red}{e}")

def menu():
    global iface
    global limit

    while True:
        print(f"{reset}{yellow}\nMenu:\n")
        print("0. Normal Sniff")
        print("1. Alert Sniff")
        print("2. Alert packet count")
        print("3. Packet Alert Limit")
        print("4. Change Interface")
        print("5. Exit")

        choice = input(f"\n{yellow}>>>{green} Enter your choice: ")

        if choice == "0":
            count = input(f"{yellow}>>> {green}Enter the number of packets to sniff or Press Enter for infinite sniffing (ctrl+C to stop): ")
            if count.strip() == "":
                 count = None
            else:
                count = int(count)

            if count is None:
                sniff(iface=iface, prn=extractor, store=0)
            else:
                sniff(iface=iface, prn=extractor, store=0, count=count)

        elif choice == "1":
            count = input(f"{yellow}>>> {green}Enter the number of packets to sniff or Press Enter for infinite sniffing (ctrl+C to stop): ")
            if count.strip() == "":
                count = None
            else:
                count = int(count)
            sniff_packets(count)

        elif choice == "2":
            display_counts()
        
        elif choice == "3":
            limit = input(f"{yellow}>>> {green}Enter the new packet limit: ")
            if limit == "":
                limit = 20
            elif limit.isnumeric():
                limit = int(limit)
                print(f"{yellow}[ok] {green}New Limit Setted!")
        
        elif choice == "4":
            print(f"\n{conf.ifaces}")
            iface = input(f"\n{yellow}>>> {green}Enter the new interface name: ")
            if iface == "":
                iface = "MediaTek Wi-Fi 6 MT7921 Wireless LAN Card"
                print(f"{yellow}[+] {green}keeping Default Interface: {blue}{iface}")
            else:
                print(f"{yellow}[ok] {green}New Interface: {blue}{iface}")
                
        elif choice == "5":
            print(f"{red}Exiting...")
            break
        else:
            print(f"{red}[!] Invalid choice")

print(f'''{blue}
███╗   ██╗███████╗████████╗███████╗██╗      ██████╗ ██╗    ██╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║     ██╔═══██╗██║    ██║
██╔██╗ ██║█████╗     ██║   █████╗  ██║     ██║   ██║██║ █╗ ██║
██║╚██╗██║██╔══╝     ██║   ██╔══╝  ██║     ██║   ██║██║███╗██║
██║ ╚████║███████╗   ██║   ██║     ███████╗╚██████╔╝╚███╔███╔╝
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝ 
      
                                       {yellow}GitHub: hoaxter
                                       MadeBy: Nitin Sikarwar
''')
menu()
