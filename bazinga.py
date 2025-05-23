from IPython import get_ipython
from IPython.display import display
# %% [markdown]
# # **Bazinga Scan**
# %%


# %%
import subprocess
import shutil
import os
import re


print("Instalando Dependências...")

# Força a remoção da pasta, se ela já existir
if os.path.exists("theHarvester"):
    shutil.rmtree("theHarvester")


# Clona novamente o repositório
subprocess.run(["git", "clone", "https://github.com/laramies/theHarvester.git"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Instala as dependências
!pip install requests beautifulsoup4 netaddr certifi aiohttp ujson dnspython aiomultiprocess censys aiodns shodan aiosqlite playwright uvloop > /dev/null 2>&1

from IPython import get_ipython
from IPython.display import display
# Verifica se nmap está instalado e instala se não estiver
!if ! which nmap > /dev/null; then apt-get update > /dev/null 2>&1 && apt-get install nmap -y > /dev/null 2>&1; fi

# Verifica se python-nmap está instalado e instala se não estiver
!if ! pip show python-nmap > /dev/null; then pip install python-nmap > /dev/null 2>&1; fi
# Verifica se o Harvester está instalado e instala se não estiver
!if ! which theHarvester > /dev/null; then git clone https://github.com/laramies/theHarvester.git > /dev/null 2>&1; fi
import nmap


## MAIN ##
def init():
  print(r"""
__________               .__                         _________
\______   \_____  _______|__| ____    _________     /   _____/ ____ _____    ____
 |    |  _/\__  \ \___   /  |/    \  / ___\__  \    \_____  \_/ ___\\__  \  /    \
 |    |   \ / __ \_/    /|  |   |  \/ /_/  > __ \_  /        \  \___ / __ \|   |  \
 |______  /(____  /_____ \__|___|  /\___  (____  / /_______  /\___  >____  /___|  /
        \/      \/      \/       \//_____/     \/          \/     \/     \/     \/ """)
  print("Seja bem vindo ao Bazinga Scan®!")
  action = input("O que gostaríamos de fazer hoje? (se quiser analisar suas opções, digite help)")
  if action.upper().strip() == "PORTSCANNING":
    alvo = input("Insira o IP ou faixa de IP's alvo: ")
    portas = input("Insira as portas que gostaria de analisar: ")
    scan_result = scan_ports(alvo, portas)
    exib_portScanning(scan_result)
  elif action.upper().strip() == "HACKERSCAN":
    alvo = input("Insira o IP ou faixa de IP's alvo: ")
    modo = input("Insira o Nível de escaneamento(1, 2 ou 3): ")
    scan_result = scan_hacker(alvo, modo)
    exib_portScanning(scan_result)
  elif action.upper().strip() == "HELP":
    print(r"""_
 _________                       .__            .___              
\______   \ ____   _____   ___  _|__| ____    __| _/____          
 |    |  _// __ \ /     \  \  \/ /  |/    \  / __ |/  _ \         
 |    |   \  ___/|  Y Y  \  \   /|  |   |  \/ /_/ (  <_> )        
 |______  /\___  >__|_|  /   \_/ |__|___|  /\____ |\____/         
        \/     \/      \/                \/      \/               
                __________               .__                      
_____    ____   \______   \_____  _______|__| ____    _________   
\__  \  /  _ \   |    |  _/\__  \ \___   /  |/    \  / ___\__  \  
 / __ \(  <_> )  |    |   \ / __ \_/    /|  |   |  \/ /_/  > __ \_
(____  /\____/   |______  /(____  /_____ \__|___|  /\___  (____  /
     \/                 \/      \/      \/       \//_____/     \/ 
  _________                   ._._.                               
 /   _____/ ____ _____    ____| | |                               
 \_____  \_/ ___\\__  \  /    \ | |                               
 /        \  \___ / __ \|   |  \|\|                               
/_______  /\___  >____  /___|  /___                               
        \/     \/     \/     \/\/\/                               """)
    print("Analise suas opções de Comando:")
    print(" ------ PortScanning ------ ")
    print("Faz um escaneamento de portas de um endereço web remotamente utilizando as tecnologias do nmap")
    print("------- HackerScan -------")
    print("Faz um scan hacker utilizando as mais incríveis ferramentas do nmap, escolha entre o nível 1, 2 ou 3")
    print("------- Subdomains -------")
    print("Enumera os subdomínios de um endereço web remotamente utilizando a ferramenta theHarvester")
    print(" Aperte \"Enter\" para escolher sua Ferramenta ! ")
    entrada = input()
    if entrada == "":
      init()
  elif action.upper().strip() == "SUBDOMAINS":
    alvo = input("Insira o domínio alvo: ")
    hosts_encontrados = enum_subdomains(alvo)

    if hosts_encontrados:
        resposta = input("Deseja executar um HackerScan nos subdomínios encontrados? (S/N): ")
        if resposta.strip().upper() == "S":
            modo = input("Escolha o nível de escaneamento (1, 2 ou 3): ")
            for host in hosts_encontrados:
                print(f"\n🔍 Executando HackerScan em: {host}")
                scan_result = scan_hacker(host, modo)
                exib_portScanning(scan_result)

## SUBDOMAINS ENUMERATION
def enum_subdomains(target):
    comando = [
        "python3", "theHarvester/theHarvester.py",
        "-d", target,
        "-b", "bing"
    ]

    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, check=True)
        saida = resultado.stdout

        # Extrair a partir de "[*] Searching Bing"
        marcador = "[*] Searching Bing"
        if marcador in saida:
            saida = saida.split(marcador, 1)[1]

        # Extrair subdomínios usando regex (ajuste conforme necessário)
        subdominios = re.findall(r'\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b', saida)

        print("✅ Subdomínios encontrados:")
        for sub in subdominios:
            print("  -", sub)

        return subdominios

    except subprocess.CalledProcessError as e:
        print("❌ Erro ao executar theHarvester:")
        print(e.stderr)
        return []

## PORT SCANNING ##
def scan_ports(target, ports):
  nm = nmap.PortScanner()
  try:
    scan = nm.scan(hosts=target, ports=ports)
    return scan
  except nmap.PortScannerError as e:
    print(f"Erro ao escanear portas: {e}")
    return None
  except nmap.PortScannerException as e:
    print(f"Erro ao escanear portas: {e}")
    return None
## HACKER SCAN ##
def scan_hacker(target, mode):
  nm = nmap.PortScanner()
  if mode == "1":
    mode = "-sS"
  elif mode == "2":
    mode = "-sS -sV"
  elif mode == "3":
    mode = "-O -sS -sV"
  elif mode == "4":
    mode = "-sN -O -sS -sV"
  try:
    scan = nm.scan(hosts=target, arguments=mode)
    return scan
  except nmap.PortScannerError as e:
    print(f"Erro ao escanear portas: {e}")
    return None

## EXPLOIT DATABASE ##
def exploitdb_search(termo):
    import urllib.parse
    query = urllib.parse.quote(termo)
    return f"https://www.exploit-db.com/search?q={query}"

## EXIBINDO DADOS ##
def exib_portScanning(scan):

    if not scan or 'scan' not in scan or not scan['scan']:
      print("Nenhum host ou porta encontrado no resultado do scan ou houve um erro no scan.")
      return
    for host in scan['scan']:
      try:
        hostname = scan['scan'][host].get('hostnames', [{'name': 'N/A'}])[0].get('name', 'N/A')
        ip_address = host
        tcp_services = scan.get('nmap', {}).get('scaninfo', {}).get('tcp', {}).get('services', 'N/A')
        print(r"""
        XXXXXXXXXXXXXXXX
    XXXXX              XXXX
   XX                     XXX
  XX                         XX
 XX  XXXXXXX        XXXXXX    XX
XX  XXXXXXXX        XXXXXX     X
X    XXXXXXX        XXXXXX     X
XX    XXXX            XXX     XX
 XX                          XX
  XXX                     XXX
    XXXXXXX          XXXXXX
          X          X
          X   X  X   X
          X   X  X   X
           XXXXXXXXXXX            """)
        print("Seu alvo foi BAZINGADO")
        print(f"\n--- Host: {hostname} ({ip_address}) ---")
        print(f"Portas analisadas: {tcp_services}")

        if 'tcp' in scan['scan'][host]:
          print("Detalhes das Portas TCP:")
          for port, port_info in scan['scan'][host]['tcp'].items():
            state = port_info.get('state', 'N/A')
            product = port_info.get('product', 'N/A')
            version = port_info.get('version', 'N/A')
            print(f"  Porta: {port} \n Estado: {state} \n Serviço: {product} \n Versão: {version}")
            print(f"\n  Link para ExploitDB: {exploitdb_search(product)}")
        else:
          print("Nenhuma porta TCP encontrada para este host.")
      except KeyError as e:
        print(f"Erro ao processar dados do host {host}: Chave esperada não encontrada - {e}")
      except Exception as e:
        print(f"Ocorreu um erro inesperado ao processar o host {host}: {e}")


init()
