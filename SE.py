import requests
import nmap
from termcolor import colored
from ipwhois import IPWhois
from colorama import init, Fore, Back, Style

print(colored("""
 ▄▀▀▀▀▄  ▄▀▀█▄   ▄▀▄▄▄▄   ▄▀▀▄ ▀▄  ▄▀▀█▄▄▄▄  ▄▀▀▄▀▀▀▄      ▄▀▀█▄▄▄▄  ▄▀▀▄ ▄▀▀▄  ▄▀▀█▀▄   ▄▀▀▀▀▄     
█ █   ▐ ▐ ▄▀ ▀▄ █ █    ▌ █  █ █ █ ▐  ▄▀   ▐ █   █   █     ▐  ▄▀   ▐ █   █    █ █   █  █ █    █      
   ▀▄     █▄▄▄█ ▐ █      ▐  █  ▀█   █▄▄▄▄▄  ▐  █▀▀█▀        █▄▄▄▄▄  ▐  █    █  ▐   █  ▐ ▐    █      
▀▄   █   ▄▀   █   █        █   █    █    ▌   ▄▀    █        █    ▌     █   ▄▀      █        █       
 █▀▀▀   █   ▄▀   ▄▀▄▄▄▄▀ ▄▀   █    ▄▀▄▄▄▄   █     █        ▄▀▄▄▄▄       ▀▄▀     ▄▀▀▀▀▀▄   ▄▀▄▄▄▄▄▄▀ 
 ▐      ▐   ▐   █     ▐  █    ▐    █    ▐   ▐     ▐        █    ▐              █       █  █         
                ▐        ▐         ▐                       ▐                   ▐       ▐  ▐         
 """, "light_red"))

intro = """
[creado por : h4]
[script name : sacnner evil]
[plataforma: github.com]
"""

print(colored(intro, "magenta"))

init(autoreset=True)



def obtener_informacion_ip(ip, api_key_ipinfo):
    try:
        url = f"https://ipinfo.io/{ip}/json?token={api_key_ipinfo}"
        response = requests.get(url)
        data = response.json()
        country = data.get('country', 'Desconocido')
        city = data.get('city', 'Desconocido')
        org = data.get('org', 'Desconocido')
        return country, city, org
    except Exception as e:
        print(f"{Fore.RED}Error al obtener la información de la IP {ip}: {e}")
        return "Desconocido", "Desconocido", "Desconocido"


def consultar_ip_virustotal(api_key, ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        resultado = response.json()
        return resultado
    else:
        print(f"{Fore.RED}Error al consultar la IP {ip} en VirusTotal. Código de estado: {response.status_code}")
        return None


def obtener_informacion_whois(ip):
    try:
        obj = IPWhois(ip)
        result = obj.lookup_whois()
        
        
        whois_info = ""
        for key, value in sorted(result.items()):
            whois_info += f"{key}: {value}\n"
        
        return whois_info
    except Exception as e:
        print(f"{Fore.RED}Error al obtener la información WHOIS para la IP {ip}: {e}")
        return "No disponible"


def obtener_puertos_nmap(ip):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=ip, arguments='-sS -Pn -p 80,443,22')
        puertos_abiertos = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    puertos_abiertos.append(f"Port: {port}, Protocolo: {proto}")
        return puertos_abiertos
    except Exception as e:
        print(f"{Fore.RED}Error al escanear puertos para la IP {ip}: {e}")
        return []


def imprimir_cuadro_verde(texto):
    cuadro = f"{Back.GREEN}{Fore.BLACK}{texto}{Style.RESET_ALL}"
    print(cuadro)

def guardar_informacion(ip, whois_info, resultado):
    if resultado:
        propietario = resultado['data']['attributes'].get('owner', 'No disponible')
        malicious = resultado['data']['attributes']['last_analysis_stats'].get('malicious', 0)
        suspicious = resultado['data']['attributes']['last_analysis_stats'].get('suspicious', 0)
        informacion_formato = f"Información de la IP:\nIP: {ip}\nPropietario: {propietario}\nMalicious: {malicious}\nSuspicious: {suspicious}\nInformación WHOIS:\n{whois_info}"
        imprimir_cuadro_verde(informacion_formato)
        with open("informacion_ips.txt", "a") as file:
            file.write(informacion_formato)
    else:
        print(f"{Fore.RED}No se pudo obtener información de la IP.")


api_key_virustotal = "b2daa0203b7b6927db3116f95a18f155c7fef895bcf574866abb949b7e8528d2"
api_key_ipinfo = "2996c72824b2fe"

while True:
    ip_input = input("Ingresa una dirección IP (o escribe 'fin' para salir): ")
    if ip_input.lower() == "fin":
        break
    resultado_virustotal = consultar_ip_virustotal(api_key_virustotal, ip_input)
    whois_info = obtener_informacion_whois(ip_input)
    puertos_nmap = obtener_puertos_nmap(ip_input)
    guardar_informacion(ip_input, whois_info, resultado_virustotal)

print("Se ha guardado la información en el archivo 'informacion_ips.txt'")