import whois
import socket
import json
import dns.resolver
from colorama import Fore, Style
import pyfiglet
import concurrent.futures
import requests

ascii_banner = pyfiglet.figlet_format("DorkPY", font="stop")
print(Fore.MAGENTA + ascii_banner + Style.RESET_ALL)

def load_service_names():
    with open('services.json') as f:
        return json.load(f)

def load_common_ports():
    with open('common_ports.json') as f:
        return json.load(f)

SERVICE_NAMES = load_service_names()
COMMON_PORTS = load_common_ports()

def find_robots_txt(domain_name):
    try:
        response = requests.get(f"http://{domain_name}/robots.txt")
        if response.status_code == 200 and "Disallow:" in response.text:
            print(Fore.GREEN + f"[+] Found robots.txt at: " + Style.RESET_ALL + f"http://{domain_name}/robots.txt" + Style.RESET_ALL)
        else:
            print(Fore.RED + f"[-] robots.txt not found for" + Style.RESET_ALL + {domain_name} + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] Error while searching for robots.txt: {e}" + Style.RESET_ALL)
        
def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                return port
    except Exception:
        pass
    return None

def scan_ports(ip_list, subdomain):
    open_ports = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(scan_port, ip, port): (ip, port) for ip in ip_list for port in COMMON_PORTS}
            for future in concurrent.futures.as_completed(future_to_port):
                ip, port = future_to_port[future]
                if (open_port := future.result()) is not None:
                    open_ports.append((ip, port))
        return open_ports
    except Exception as e:
        print(Fore.RED + f"[-] Port scanning failed for subdomain {subdomain}: {e}" + Style.RESET_ALL)
        return []

try:
    domain_name = input("Enter the domain name (e.g., example.com): ")
    ip = socket.gethostbyname(domain_name)
    info = whois.whois(domain_name)

    print("\n" + Fore.MAGENTA + "[*] Domain Information:" + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Domain Name:" + Style.RESET_ALL, domain_name)
    print(Fore.GREEN + "[+] Registration Name:" + Style.RESET_ALL, info.get('registrant_name'))
    print(Fore.GREEN + "[+] Registration ID:" + Style.RESET_ALL, info.get('registrant_id'))
    print(Fore.GREEN + "[+] Country:" + Style.RESET_ALL, info.get('country'))
    print(Fore.GREEN + "[+] Expiration Date:" + Style.RESET_ALL, info.get('expiration_date'))
    print(Fore.GREEN + "[+] Status:" + Style.RESET_ALL, info.get('status'))
    print(Fore.GREEN + "[+] Person:" + Style.RESET_ALL, info.get('name'))
    print(Fore.GREEN + "[+] Email:" + Style.RESET_ALL, info.get('email'))

    print("\n" + Fore.MAGENTA + "[*] Subdomains found..." + Style.RESET_ALL)
    ip_list = []
    try:
        answers = dns.resolver.resolve(domain_name, 'A')
        for rdata in answers:
            subdomain_ip = rdata.address
            ip_list.append(subdomain_ip)
            print(Fore.GREEN + f"[+] IP Address:" + Style.RESET_ALL + f" {subdomain_ip}")
    except Exception as e:
        print(Fore.RED + f"[-] Subdomain scanning failed: {e}" + Style.RESET_ALL)

    print("\n" + Fore.MAGENTA + "[*] Scanning Open Ports..." + Style.RESET_ALL)
    try:
        open_ports = scan_ports(ip_list, domain_name)
        for ip, port in open_ports:
            print(Fore.GREEN + f"[+] Port:" + Style.RESET_ALL + f" {port} | " + Fore.GREEN + f"Service:" + Style.RESET_ALL + f" {SERVICE_NAMES.get(str(port), 'Unknown')}" + Style.RESET_ALL + f" | " + Fore.GREEN + f"Subdomain:" + Style.RESET_ALL + f" {ip}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] Port scanning failed: {e}" + Style.RESET_ALL)
        
    print("\n" + Fore.MAGENTA + "[*] Finding robots.txt..." + Style.RESET_ALL)
    find_robots_txt(domain_name)


    print("\n" + Fore.BLUE + f"[#] Leaving..." + Style.RESET_ALL)
except Exception as e:
    print(Fore.RED + f"[-] Something Went Wrong: {e}" + Style.RESET_ALL)
