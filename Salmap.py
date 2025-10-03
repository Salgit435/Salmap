#!/usr/bin/env python3

import sys
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address, ip_network

# Suppress Scapy's verbose welcome message and IPv6 warnings
os.environ["SCAPY_SILENCE_WARNINGS"] = "1"
try:
    import scapy.all as scapy
except ImportError:
    print("\n[!] Scapy is not installed. Please run: pip install scapy")
    sys.exit(1)

# --- UI and Helper Classes ---
class Colors:
    RESET = '\033[0m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    CYAN = '\033[36m'

# --- Core Scanning Logic ---
open_ports = []
lock = threading.Lock()

def check_host(target):
    """Performs an ICMP ping to see if the host is online."""
    print(f"{Colors.YELLOW}[*] Pinging {target} to check its status...{Colors.RESET}")
    try:
        # Craft an ICMP echo-request packet
        packet = scapy.IP(dst=target) / scapy.ICMP()
        # Send packet and wait for one reply, timeout of 2 seconds
        response = scapy.sr1(packet, timeout=2, verbose=0)
        
        if response:
            print(f"{Colors.GREEN}[+] Host {target} is up!{Colors.RESET}")
            return True
        else:
            print(f"{Colors.RED}[-] Host {target} appears to be down or is not responding to pings.{Colors.RESET}")
            return False
    except Exception as e:
        print(f"{Colors.RED}[!] An error occurred during ping: {e}{Colors.RESET}")
        return False

def scan_port(target_ip, port):
    """Scans a single port using a TCP SYN scan."""
    try:
        # Craft a TCP SYN packet
        src_port = scapy.RandShort()
        packet = scapy.IP(dst=target_ip) / scapy.TCP(sport=src_port, dport=port, flags="S")
        
        # Send the packet and wait for a response
        response = scapy.sr1(packet, timeout=1, verbose=0)

        if response and response.haslayer(scapy.TCP):
            # Check the flags in the TCP layer of the response
            # 0x12 is SYN/ACK, which means the port is open
            if response.getlayer(scapy.TCP).flags == 0x12:
                with lock:
                    print(f"{Colors.GREEN}[+] Port {port} is open{Colors.RESET}")
                    open_ports.append(port)
                # Send a RST packet to close the connection gracefully
                scapy.send(scapy.IP(dst=target_ip) / scapy.TCP(sport=src_port, dport=port, flags="R"), verbose=0)

    except Exception as e:
        # This will catch errors if scapy has issues
        pass

def perform_port_scan(target, ports_str):
    """Manages the multi-threaded port scanning process."""
    global open_ports
    open_ports = []

    try:
        # Parse the ports string (e.g., "80,443" or "1-1024")
        ports_to_scan = []
        if '-' in ports_str:
            start, end = map(int, ports_str.split('-'))
            ports_to_scan = range(start, end + 1)
        elif ',' in ports_str:
            ports_to_scan = map(int, ports_str.split(','))
        else:
            ports_to_scan = [int(ports_str)]
    except ValueError:
        print(f"{Colors.RED}[!] Invalid port specification. Use '80', '80,443', or '1-1024'.{Colors.RESET}")
        return

    print(f"\n{Colors.YELLOW}[*] Starting TCP SYN scan on {target}...{Colors.RESET}")
    # Use a thread pool to scan ports concurrently for speed
    with ThreadPoolExecutor(max_workers=50) as executor:
        # map() will apply the scan_port function to every port in the list
        executor.map(lambda port: scan_port(target, port), ports_to_scan)

    print(f"\n{Colors.GREEN}[+] Scan complete.{Colors.RESET}")
    if open_ports:
        print(f"{Colors.CYAN}Open ports found: {sorted(open_ports)}{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}No open TCP ports found in the specified range.{Colors.RESET}")


# --- UI and Menu Functions ---
def show_banner_and_disclaimer():
    """Displays the tool's banner and ethical use disclaimer."""
    banner = f"""
{Colors.CYAN}
   ███████╗ █████╗ ██╗      ██████╗  █████╗ ██████╗ 
   ██╔════╝██╔══██╗██║     ██╔═══██╗██╔══██╗██╔══██╗
   ███████╗███████║██║     ██║   ██║███████║██████╔╝
   ╚════██║██╔══██║██║     ██║   ██║██╔══██║██╔═══╝ 
   ███████║██║  ██║███████╗╚██████╔╝██║  ██║██║     
   ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     
{Colors.RESET}
       {Colors.YELLOW}A Custom-Built Ethical Network Scanner{Colors.RESET}
    """
    print(banner)
    print(f"{Colors.RED}{'='*60}")
    print(f"{Colors.YELLOW}{'*** LEGAL & ETHICAL USE DISCLAIMER ***'.center(60)}{Colors.RESET}")
    print(f"{Colors.RED}{'='*60}")
    print(f"""
{Colors.YELLOW}1. {Colors.RESET}This tool is intended for {Colors.GREEN}ethical{Colors.RESET} and {Colors.GREEN}authorized{Colors.RESET} security auditing.
{Colors.YELLOW}2. {Colors.RESET}You must have {Colors.RED}explicit, written permission{Colors.RESET} from the network
   owner before scanning any system.
{Colors.YELLOW}3. {Colors.RESET}Unauthorized scanning is {Colors.RED}illegal{Colors.RESET}. The author is not responsible
   for any misuse or damage caused by this tool.
""")
    try:
        agreement = input(f"{Colors.CYAN}Do you agree to use this tool ethically and legally? (yes/no): {Colors.RESET}").lower()
        if agreement != 'yes':
            print(f"\n{Colors.RED}Agreement not given. Exiting.{Colors.RESET}")
            sys.exit(0)
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Operation cancelled. Exiting.{Colors.RESET}")
        sys.exit(0)

def check_privileges():
    """Checks for root privileges, required for raw socket operations."""
    if os.geteuid() != 0:
        print(f"{Colors.RED}[!] This script uses raw sockets and requires root privileges.")
        print(f"{Colors.YELLOW}[*] Please run it with: sudo ./salmap.py{Colors.RESET}")
        sys.exit(1)

def main_menu():
    """Displays the main menu and handles user interaction."""
    target = ""
    while True:
        os.system('clear')
        print(f"{Colors.CYAN}{'SaLMaP - Main Menu'}{Colors.RESET}")
        print("--------------------")
        if target:
            print(f"{Colors.GREEN}Current Target: {target}{Colors.RESET}\n")
        else:
            print(f"{Colors.YELLOW}No target set.{Colors.RESET}\n")
        
        print(f"{Colors.YELLOW}1.{Colors.RESET} Set Target (IP or Domain)")
        print(f"{Colors.YELLOW}2.{Colors.RESET} Check if Host is Online (Ping)")
        print(f"{Colors.YELLOW}3.{Colors.RESET} Scan Top 20 Common Ports")
        print(f"{Colors.YELLOW}4.{Colors.RESET} Scan Custom Port Range (e.g., 1-1000)")
        print(f"\n{Colors.RED}9.{Colors.RESET} Exit")
        print("--------------------")

        choice = input(f"{Colors.GREEN}Enter your choice: {Colors.RESET}")

        if choice == '1':
            target = input(f"{Colors.CYAN}Enter target IP or domain: {Colors.RESET}")
        elif choice == '2':
            if target:
                check_host(target)
            else:
                print(f"{Colors.RED}[!] Please set a target first.{Colors.RESET}")
        elif choice == '3':
            if target:
                # Top 20 most common ports
                common_ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"
                perform_port_scan(target, common_ports)
            else:
                print(f"{Colors.RED}[!] Please set a target first.{Colors.RESET}")
        elif choice == '4':
            if target:
                ports_str = input(f"{Colors.CYAN}Enter port range (e.g., 1-1024 or 80,443): {Colors.RESET}")
                perform_port_scan(target, ports_str)
            else:
                print(f"{Colors.RED}[!] Please set a target first.{Colors.RESET}")
        elif choice == '9':
            print(f"{Colors.BLUE}Thank you for using SaLMaP ethically. Goodbye!{Colors.RESET}")
            sys.exit(0)
        else:
            print(f"\n{Colors.RED}[!] Invalid choice. Please try again.{Colors.RESET}")
        
        if choice in ['2','3','4']:
            input(f"\n{Colors.YELLOW}Press Enter to return to the menu...{Colors.RESET}")


if __name__ == "__main__":
    os.system('clear')
    show_banner_and_disclaimer()
    check_privileges()
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}Operation cancelled by user. Exiting.{Colors.RESET}")
        sys.exit(0)
