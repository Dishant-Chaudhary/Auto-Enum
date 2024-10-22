import socket
import subprocess
import whois
import os
import requests
import pyfiglet
from termcolor import colored
from datetime import datetime

# Print banner
def print_banner():
    banner_text = pyfiglet.figlet_format("AutoEnum")
    colored_banner = colored(banner_text, 'cyan')
    print(colored_banner)

    description = colored("Automate domain, IP, and port scanning", 'yellow')
    line = colored("=" * 55, 'green')
    
    print(f"{line}")
    print(f"| {description.center(53)} |")
    print(f"{line}\n")

# Get WHOIS information for a domain
def domain_whois(domain):
    try:
        print(f"\n[*] Getting WHOIS information for domain: {domain}")
        result = subprocess.check_output(['whois', domain], encoding='utf-8')
        print(result)
    except Exception as e:
        print(f"[!] Error getting WHOIS information: {e}")

# DNS lookup for domain
def dns_lookup(domain):
    try:
        print(f"\n[*] Performing DNS lookup for domain: {domain}")
        ip_address = socket.gethostbyname(domain)
        print(f"Domain {domain} resolves to IP: {ip_address}")
        return ip_address
    except Exception as e:
        print(f"[!] Error resolving domain: {e}")
        return None

# Port scanning using Nmap with customizable options
def run_nmap_scan(ip, nmap_options):
    print(f"\n[*] Running Nmap scan on IP: {ip} with options: {nmap_options}")
    try:
        # Build Nmap command dynamically
        command = f"nmap {nmap_options} {ip}"
        scan_result = subprocess.check_output(command.split(), encoding='utf-8')
        print(scan_result)
    except Exception as e:
        print(f"[!] Error running Nmap scan: {e}")

# Subdomain enumeration using SecurityTrails API
def subdomain_enum(domain):
    print(f"\n[*] Enumerating subdomains for: {domain} using Sublist3r")
    
    try:
        # Create a unique file name using the domain and current timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"subdomains_{domain}_{timestamp}.txt"

        # Run Sublist3r globally without specifying a path
        command = f"sublist3r -d {domain} -o {output_file}"
        subprocess.run(command, shell=True, check=True)

        # Read results from the unique output file
        with open(output_file, "r") as file:
            subdomains = file.readlines()

        if subdomains:
            print(f"[+] Found {len(subdomains)} subdomains:")
            for subdomain in subdomains:
                print(f"- {subdomain.strip()}")
        else:
            print("[!] No subdomains found.")
        
        print(f"\n[+] Results saved to {output_file}")
    
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running Sublist3r: {e}")
    except Exception as e:
        print(f"[!] Error enumerating subdomains: {e}")

# Reverse DNS lookup
def reverse_dns(ip):
    try:
        print(f"\n[*] Performing reverse DNS lookup for IP: {ip}")
        domain = socket.gethostbyaddr(ip)
        print(f"[+] The reverse DNS of {ip} is {domain[0]}")
    except Exception as e:
        print(f"[!] Error performing reverse DNS: {e}")

# Vulnerability check based on service version (placeholder)
def vulnerability_check(service):
    print(f"\n[*] Checking for known vulnerabilities in {service}...")
    # Placeholder: In real use, query CVE databases or use other tools
    print(f"[+] No known vulnerabilities found for {service}")

# Main function to execute tool
def main():
    print_banner()

    # Get user input
    target_domain = input("\n[?] Enter domain to enumerate: ")
    if not target_domain:
        print("[!] No domain provided, exiting...")
        return

    # Get WHOIS info
    domain_whois(target_domain)

    # DNS lookup
    ip = dns_lookup(target_domain)

    if ip:
        # Reverse DNS lookup
        reverse_dns(ip)

        # Ask user for Nmap options
        print("\n[?] Choose Nmap scanning options:")
        print("1 - Aggressive Scan (-A)")
        print("2 - Top 10 Ports (--top-ports 10)")
        print("3 - Service Detection (-sV)")
        print("4 - OS Detection (-O)")
        print("5 - Custom (Enter your own options)")
        choice = input("[?] Enter choice (1-5): ")

        nmap_options = ''
        if choice == '1':
            nmap_options = '-A'
        elif choice == '2':
            nmap_options = '--top-ports 10'
        elif choice == '3':
            nmap_options = '-sV'
        elif choice == '4':
            nmap_options = '-O'
        elif choice == '5':
            nmap_options = input("[?] Enter custom Nmap options: ")
        else:
            print("[!] Invalid choice, defaulting to -sV")
            nmap_options = '-sV'

        # Run Nmap scan with chosen options
        run_nmap_scan(ip, nmap_options)

        # Subdomain enumeration
        subdomain_enum(target_domain)

        # Vulnerability check placeholder
        vulnerability_check("ExampleService")

    else:
        print("[!] Unable to proceed without valid IP address.")

if __name__ == "__main__":
    main()