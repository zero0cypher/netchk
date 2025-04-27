# Análisis de Redes IP

Este script en Python está diseñado para analizar direcciones IP (tanto IPv4 como IPv6) y redes. A partir de una dirección IP o una dirección con su máscara de subred, el script proporciona información detallada sobre la red, incluyendo:

- **Clase de la red**: Determina si la red pertenece a las clases A, B, C, etc.
- **Dirección de red**: Muestra la dirección de la red sin la máscara.
- **Máscara de subred**: Incluye la máscara de subred asociada.
- **Cantidad de hosts disponibles**: Calcula cuántos dispositivos pueden existir en la red.
- **Prueba de conectividad**: Realiza un ping para verificar la accesibilidad de la dirección.
- **Escaneo de puertos**: Utiliza Nmap para escanear puertos abiertos y servicios activos.

## Funcionalidades:
1. **Análisis de dirección IP o red**:
   - Soporta direcciones IPv4 y IPv6.
   - Detecta automáticamente si la entrada es una red (con máscara) o una IP individual.
   - Calcula el número de hosts disponibles según la clase de la red.

2. **Prueba de conectividad**:
   - Realiza un `ping` para comprobar si la dirección está activa.

3. **Escaneo de puertos con Nmap**:
   - Realiza un escaneo básico de puertos abiertos en la dirección o red especificada.

## Requisitos:
- Python 3.x
- Bibliotecas necesarias:
  - `ipaddress` (integrada en Python estándar)
  - `subprocess` (integrada en Python estándar)
  - `nmap` (si se desea realizar escaneo de puertos con Nmap)

## Uso:
Puedes ejecutar el script desde la línea de comandos proporcionando una dirección IP o una red con máscara, como se muestra a continuación:

```bash
python script.py <IP o IP/Máscara>
