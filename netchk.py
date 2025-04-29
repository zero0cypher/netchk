import ipaddress
import subprocess
import platform
import nmap  
import sys

# === Funcion para validar y procesar la IP ===
def procesar_direccion(ip_input):
    print("=== Validating IP Address")
    try:
        if( ("/") in ip_input):
            obj = ipaddress.ip_network(ip_input)
            return obj
        else:
            obj = ipaddress.ip_address(ip_input)
            return obj
    except ValueError:
        print("Address not valid")
        return

# === Funcion para obtener clase y datos de red ===
def analizar_red(red):
    # Determinar clase A, B, C, etc.
    # Calcular host disponibles, rango valido, etc.
    if isinstance(red, ipaddress.IPv4Network):
        version = red.version
        address = red.network_address
        broadcast = red.broadcast_address
        num_address = red.num_addresses
        firs_octet = int(str(address).split('.')[0])
        
        if(1 <= firs_octet <= 126):
            print('IP Address Class :A')
        elif(128 <= firs_octet <= 191):
            print('IP Address Class :B')
        elif(192 <= firs_octet <= 223):
            print('IP Address Class :C')
        elif(224 <= firs_octet <= 239):
            print('IP Address Class :D (Multicast)')
        elif(240 <= firs_octet <= 254):
            print('IP Address Class :E (Reserved)')

        print("IP Addres Version:",version)
        print("IP Addres:",address)
        print("BroadCast Address:",broadcast)
        print("Total Number of Hosts:",num_address)

    elif isinstance(red, ipaddress.IPv6Network):
        version = red.version
        address = red.network_address
        num_addresses = red.num_addresses
        is_private = red.is_private
        is_link_local = red.is_link_local
        is_multicast = red.is_multicast
        is_reserved = red.is_reserved
        is_loopback = red.is_loopback
        is_global = red.is_global

        # Determinar tipo
        if is_loopback:
            tipo = "Loopback (::1)"
        elif is_link_local:
            tipo = "Link-local"
        elif is_multicast:
            tipo = "Multicast"
        elif is_private:
            tipo = "Unique local (privada)"
        elif is_global:
            tipo = "Global Unicast"
        elif is_reserved:
            tipo = "Reserved"
        else:
            tipo = "Unkown"

        # Mostrar resultados
        print(f"IP Address Version: {version}")
        print(f"IPv6 Network Address: {address}")
        print(f"Total Number of Addresses: {num_addresses}")
        print(f"Tipo de dirección: {tipo}")

    elif isinstance(red, ipaddress.IPv4Address): 

        print(f"Dirección: {red}")
        print(f"Loopback: {red.is_loopback}")
        print(f"Privada: {red.is_private}")
        print(f"Multicast: {red.is_multicast}")
        print(f"Reservada: {red.is_reserved}")
        print(f"Global: {red.is_global}")
        print(f"Versión: {red.version}")
    
    elif isinstance(red, ipaddress.IPv6Address) :

        print(f"Dirección: {red}")
        print(f"Loopback: {red.is_loopback}")
        print(f"Link-local: {red.is_link_local}")
        print(f"Privada (ULA): {red.is_private}")
        print(f"Multicast: {red.is_multicast}")
        print(f"Reservada: {red.is_reserved}")
        print(f"Global: {red.is_global}")
        print(f"Versión: {red.version}")
        

# === Funcion para prueba de conectividad ===
def prueba_conectividad(ip):

    if isinstance(ip, ipaddress.IPv4Network):
        address = ip.network_address
    elif isinstance(ip, ipaddress.IPv6Network):
        address = ip.network_address
    else:
        address = ip

    try:
        system = platform.system().lower()
        if system == "windows":
            command = ["ping","-n","1", address]
        else:
            command = ["ping","-c","1", address]
        
        answer = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if answer.returncode == 0:
            print(f"{address} is reachable.")
        else:
            print(f"Cant reach {address}.")
    except Exception as e:
        print(f"Error: {e}")

def scan_target(target):

    try:
        network = ipaddress.ip_network(target, strict=False)
        print(f"Scanning network {target}...")
        for ip in network.hosts():  #
            scan_ip(str(ip))
    except ValueError:
        print(f"Scanning single IP {target}...")
        scan_ip(target)

def scan_ip(ip):

    scanner = nmap.PortScanner()
    
    params = '-sS -sV -O -T4 -F' 

    scanner.scan(hosts=ip, arguments=params)

    for host in scanner.all_hosts():
        print(f"\nHost: {host} ({scanner[host].hostname()})")
        print(f"State: {scanner[host].state()}")

        for proto in scanner[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = scanner[host][proto].keys()
            for port in sorted(ports):
                state = scanner[host][proto][port]['state']
                print(f"Port: {port} - State: {state}")

        if 'osmatch' in scanner[host]:
            for os in scanner[host]['osmatch']:
                print(f"Operating System: {os['name']}")

        if 'version' in scanner[host]:
            for service in scanner[host]['version']:
                print(f"Service: {service} - Version: {scanner[host]['version'][service]}")

def main():
    print("=== Network Checker ===")

    if len(sys.argv) != 2:
        print("Use of Script: python script.py <IP o IP/Mask>")
        sys.exit(1)

    ip_input = sys.argv[1]

    red = procesar_direccion(ip_input)
    if not red:
        print("Input not valid")
        return

    info_red = analizar_red(red)
    estado_ping = prueba_conectividad(red)
    scan_target(red)


# === Punto de entrada ===
if __name__ == "__main__":
    main()
