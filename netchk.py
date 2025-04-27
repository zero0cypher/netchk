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
            obj = ipaddress.ipaddress(ip_input)
            return obj
    except ValueError:
        print("Address not valid")
        return

# === Funcion para obtener clase y datos de red ===
def analizar_red(red):
    # Determinar clase A, B, C, etc.
    # Calcular host disponibles, rango valido, etc.
    if(isinstance(red, ipaddress.IPv4Network)):
        version = red.version
        address = red.network_address
        broadcast = red.broadcast_address
        num_address = red.num_address
        print("IP Addres Version:",version)

    elif(isinstance(red, ipaddress.IPv6Network)):
    elif(isinstance(red, ipaddress.IPv4Address)): 
    elif(isinstance(red, ipaddress.IPv6Address))
    pass

# === Funcion para prueba de conectividad ===
def prueba_conectividad(ip):
    # Realizar ping dependiendo del sistema operativo
    pass

# === Funcion para escanear con Nmap ===
def escanear_nmap(ip):
    # Llamar a nmap y capturar resultado
    pass

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
    estado_ping = prueba_conectividad(str(red.network_address))
    resultado_nmap = escanear_nmap(str(red.network_address))


# === Punto de entrada ===
if __name__ == "__main__":
    main()
