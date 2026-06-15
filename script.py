#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Diagnóstico de rede para PS Remote Play (PS4/PS5)
==================================================

Coleta informações de sistema, rede, DNS, proxy, firewall e conectividade
para ajudar a identificar por que o PS Remote Play não conecta em uma
determinada rede (ex: rede corporativa).

Como executar
--------------
Windows : python script.py   (ou: py script.py)
          De preferência abra o PowerShell/CMD como "Administrador" -
          isso ajuda a seção de Endpoints UDP a mostrar mais detalhes.

Linux   : python3 script.py
          Algumas seções usam 'sudo' automaticamente (iptables, ss -p).
          Se aparecer "requer sudo", rode: sudo python3 script.py

Saída
-----
Gera o arquivo 'remoteplay_diagnostico.txt' na mesma pasta do script,
em UTF-8, com cada seção e uma nota explicando como interpretar o
resultado / o que fazer se der erro.
"""

import os
import platform
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime

IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    # Coloca o console desta sessão (e o stdout do Python) em UTF-8, para
    # as mensagens "[*] ..." abaixo aparecerem com acentos corretos.
    try:
        os.system("chcp 65001 >nul")
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

REPORT = []
PS_HOST = "remoteplay.dl.playstation.net"  # mesmo host já usado no script original


# ---------------------------------------------------------------------------
# Funções auxiliares
# ---------------------------------------------------------------------------

def _windows_oem_encoding():
    """Codepage OEM do Windows (usado por ipconfig/route/ping/tracert/nslookup)."""
    try:
        import ctypes
        return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
    except Exception:
        return "cp850"


WINDOWS_OEM_ENCODING = _windows_oem_encoding() if IS_WINDOWS else None


def _decode_console_output(data: bytes) -> str:
    """
    Decodifica a saída de um comando do Windows.

    Comandos baseados em PowerShell/netsh respeitam o 'chcp 65001' e saem
    em UTF-8. Já utilitários antigos (ipconfig, route, ping, tracert,
    nslookup) ignoram o 'chcp' quando a saída é redirecionada e continuam
    usando o codepage OEM do sistema (no Brasil, geralmente cp850/cp860) -
    é o que causava acentos quebrados como "Configura‡Æo".

    Estratégia: tenta UTF-8 primeiro; se os bytes não forem UTF-8 válido,
    usa o codepage OEM detectado.
    """
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode(WINDOWS_OEM_ENCODING, errors="replace")


def step(msg):
    """Mostra progresso no console enquanto o script roda."""
    print(f"[*] {msg}")


def run(win_cmd, linux_cmd=None, timeout=30):
    """
    Executa um comando do sistema e devolve a saída como texto.

    win_cmd / linux_cmd: comandos equivalentes para cada SO. Se linux_cmd
    for None e o script estiver rodando em Linux, a seção é marcada como
    "não aplicável" em vez de tentar rodar um comando do Windows.

    Erros comuns e o que significam:
    - [TIMEOUT]: o comando não respondeu dentro do tempo limite. Em
      testes de rede isso costuma indicar que os pacotes estão sendo
      DESCARTADOS (DROP) por um firewall - sem resposta, sem erro,
      apenas silêncio até o tempo esgotar.
    - [ERRO] FileNotFoundError / "comando não encontrado": o utilitário
      não está instalado neste SO. No Linux, instale o que faltar, ex:
          sudo apt install iproute2 dnsutils traceroute net-tools
    - Linhas pedindo "sudo": rode o script novamente com 'sudo
      python3 script.py' para esta seção sair completa.
    """
    cmd = win_cmd if IS_WINDOWS else linux_cmd
    if cmd is None:
        return "(comando não aplicável a este sistema operacional)"

    if IS_WINDOWS:
        # Força o console para UTF-8 antes do comando, evitando acentos
        # quebrados (ex: "Configura‡Æo" em vez de "Configuração").
        cmd = f"chcp 65001>nul && {cmd}"

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            timeout=timeout,
        )
        if IS_WINDOWS:
            out = _decode_console_output(result.stdout).strip()
            err = _decode_console_output(result.stderr).strip()
        else:
            out = result.stdout.decode("utf-8", errors="replace").strip()
            err = result.stderr.decode("utf-8", errors="replace").strip()

        if not out and err:
            out = err
        elif err:
            out += f"\n\n[stderr]\n{err}"
        return out if out else "(sem saída - comando não retornou nada)"
    except subprocess.TimeoutExpired:
        return (
            f"[TIMEOUT] Sem resposta em {timeout}s.\n"
            "Possível pacote descartado (DROP) por firewall no caminho."
        )
    except FileNotFoundError as e:
        return f"[ERRO] Comando não encontrado: {e}"
    except Exception as e:
        return f"[ERRO] {type(e).__name__}: {e}"


def add(title, content, note=None):
    REPORT.append(f"\n{'=' * 80}")
    REPORT.append(title)
    REPORT.append(f"{'=' * 80}")
    REPORT.append(content)
    if note:
        REPORT.append("\n--- Como interpretar / o que fazer ---")
        REPORT.append(note)


def tcp_port_test(host, port, timeout=4):
    """
    Testa uma porta TCP usando sockets puros do Python - funciona igual
    no Windows e no Linux, sem depender de PowerShell, nc, telnet etc.

    Retorna (ok: bool, mensagem: str). Possíveis mensagens:
    - "OK - conectado em Xms"        -> porta aberta e alcançável.
    - "Timeout (...)"                -> sem resposta. Em redes
      corporativas costuma indicar firewall em modo DROP.
    - "Conexão recusada (RST)"       -> chegou no destino, mas a porta
      está fechada LÁ (não é bloqueio no meio do caminho).
    - "Erro de resolução DNS"        -> o hostname não resolveu.
    """
    try:
        start = datetime.now()
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (datetime.now() - start).total_seconds() * 1000
            return True, f"OK - conectado em {elapsed:.0f} ms"
    except socket.gaierror:
        return False, "Erro de resolução DNS (host não encontrado)"
    except ConnectionRefusedError:
        return False, "Conexão recusada (RST) - porta fechada no destino"
    except (socket.timeout, TimeoutError):
        return False, f"Timeout após {timeout}s - sem resposta (possível DROP no caminho)"
    except OSError as e:
        return False, f"Erro de rede: {e}"


def http_status(url, timeout=10):
    """
    Faz uma requisição HTTPS e devolve o status (ou descrição do erro).

    Erros comuns:
    - HTTPError -> servidor respondeu, mas com 4xx/5xx (conexão OK).
    - SSLCertVerificationError -> certificado não confiável. Em redes
      corporativas costuma indicar PROXY DE INSPEÇÃO SSL (a empresa
      troca o certificado real pelo dela).
    - URLError "timed out"            -> sem resposta (DROP).
    - URLError "Connection refused"   -> RST no caminho ou destino.
    - URLError "getaddrinfo failed"   -> falha de DNS.
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return f"{resp.status} {resp.reason}"
    except urllib.error.HTTPError as e:
        return f"{e.code} {e.reason} (servidor respondeu com erro HTTP)"
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            return (
                f"[ERRO SSL] {reason}\n"
                "-> Possível inspeção SSL corporativa (proxy MITM) "
                "trocando o certificado."
            )
        return f"[ERRO DE CONEXÃO] {reason}"
    except Exception as e:
        return f"[ERRO] {type(e).__name__}: {e}"


def get_public_ip():
    """Tenta vários serviços, sem depender da lib 'requests'."""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=8) as resp:
                return resp.read().decode().strip()
        except Exception:
            continue
    return "[ERRO] Não foi possível obter o IP público (sem internet, DNS bloqueado ou proxy obrigatório)"


def is_admin():
    """Retorna True/False/None (indeterminado) se está elevado (admin/root)."""
    try:
        if IS_WINDOWS:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return None


def ask(prompt):
    """input() que não trava o script se não houver terminal interativo."""
    try:
        return input(prompt).strip().lower()
    except (EOFError, OSError):
        return ""


# ---------------------------------------------------------------------------
# Pergunta rápida sobre o teste do Remote Play (para registrar no relatório)
# ---------------------------------------------------------------------------

print("Iniciando diagnóstico do PS Remote Play...")
print(f"Sistema detectado: {platform.system()} - rodando como administrador/root: {is_admin()}\n")

print("Antes de coletar os dados, responda sobre a ÚLTIMA tentativa de uso do")
print("PS Remote Play nesta rede (pressione Enter para pular qualquer pergunta):\n")

rp_ok = ask("O PS Remote Play conseguiu conectar agora? (s/n/Enter=não testei): ")

rp_detail = ""
if rp_ok == "n":
    rp_detail = ask(
        "\nNa tentativa, o app chegou a MOSTRAR o PS5 na lista de consoles?\n"
        "  a) Sim, apareceu na lista, mas a conexão falhou depois\n"
        "  b) Não, o PS5 nunca apareceu na lista (fica 'procurando')\n"
        "Resposta (a/b/Enter=não sei): "
    )

if rp_ok == "s":
    rp_status_text = "SUCESSO - o usuário confirmou que o PS Remote Play conectou nesta tentativa."
elif rp_ok == "n":
    if rp_detail == "a":
        rp_status_text = (
            "FALHA - o PS5 apareceu na lista de consoles, mas a conexão falhou "
            "(problema na fase de streaming/dados)."
        )
    elif rp_detail == "b":
        rp_status_text = (
            "FALHA - o PS5 nunca apareceu na lista de consoles "
            "(problema na fase de descoberta/broadcast local)."
        )
    else:
        rp_status_text = "FALHA - o usuário confirmou que o PS Remote Play NÃO conectou nesta tentativa."
else:
    rp_status_text = "Não informado pelo usuário."

print()


# ---------------------------------------------------------------------------
# Coleta de informações
# ---------------------------------------------------------------------------

add(
    "Sobre este script",
    (
        "Este relatório foi gerado automaticamente para ajudar a diagnosticar\n"
        "falhas de conexão do PS Remote Play.\n\n"
        f"Sistema operacional : {platform.system()} ({platform.platform()})\n"
        f"Executando elevado  : {is_admin()}\n"
        f"PS Remote Play agora: {rp_status_text}\n\n"
        "Cada seção abaixo tem um bloco '--- Como interpretar / o que fazer ---'\n"
        "explicando o que o resultado significa e como corrigir problemas comuns.\n\n"
        "No Linux, se algum comando faltar, instale os pacotes básicos:\n"
        "  sudo apt update && sudo apt install -y iproute2 dnsutils net-tools \\\n"
        "       traceroute iputils-ping curl"
    ),
)

step("Coletando informações do sistema...")
add(
    "Sistema",
    f"""
Data: {datetime.now()}
Host: {socket.gethostname()}
SO: {platform.platform()}
"""
)

step("Consultando IP público...")
add(
    "IP Público",
    get_public_ip(),
    note=(
        "Se vier um IP de datacenter/outro país, o tráfego pode estar saindo\n"
        "por um proxy/VPN corporativo - o que pode afetar a geolocalização\n"
        "usada pela Sony/PSN.\n"
        "Se vier '[ERRO]': sem internet, DNS bloqueado para esses domínios,\n"
        "ou a rede exige proxy para qualquer saída HTTP/HTTPS."
    )
)

step("Coletando configuração de rede (IP/rotas)...")
add(
    "Configuração de Rede (IPCONFIG / IP)",
    run(
        "ipconfig /all",
        "ip address show; echo ---ROTAS---; ip route show"
    ),
    note=(
        "Verifique:\n"
        "- 'Gateway Padrão' / 'default via': deve ser o roteador da rede atual.\n"
        "- 'Servidores DNS': se for um IP corporativo (ex: Cisco Umbrella/\n"
        "  OpenDNS, como 208.67.222.222), o DNS pode filtrar domínios de\n"
        "  jogos/streaming mesmo que o domínio 'pareça' resolver.\n\n"
        "Linux: se 'ip' não existir, instale 'iproute2' ou use 'ifconfig -a'\n"
        "(pacote net-tools)."
    )
)

step("Listando adaptadores de rede...")
add(
    "Adaptadores de Rede",
    run(
        'powershell "Get-NetAdapter | Format-Table Name,Status,LinkSpeed,MacAddress -AutoSize"',
        "ip -br link show"
    ),
    note=(
        "Confira se existe mais de um adaptador 'Up' ao mesmo tempo (ex: Wi-Fi\n"
        "e Ethernet juntos, ou um adaptador virtual de VPN ativo) - isso pode\n"
        "fazer o tráfego sair por uma rota inesperada."
    )
)

step("Coletando tabela de rotas...")
add(
    "Tabela de Rotas",
    run(
        "route print",
        "ip route show; echo ---IPv6---; ip -6 route show 2>/dev/null"
    ),
    note=(
        "A rota padrão (0.0.0.0/0 ou 'default') mostra para qual gateway o\n"
        "tráfego sai. Em redes corporativas esse gateway costuma ser um\n"
        "firewall (Fortigate, Palo Alto, Cisco ASA, etc.) que filtra por\n"
        "porta/protocolo/categoria de aplicação."
    )
)

step("Resolvendo DNS...")
add(
    "Resolução DNS (Remote Play)",
    run(
        f"nslookup {PS_HOST}",
        f"getent ahostsv4 {PS_HOST} || nslookup {PS_HOST} || host {PS_HOST}"
    ),
    note=(
        "Se não resolver, ou resolver para um IP estranho (ex: IP interno da\n"
        "empresa ou 0.0.0.0), o DNS corporativo provavelmente está\n"
        "bloqueando/redirecionando o domínio (sinkhole).\n\n"
        "Linux: se 'nslookup'/'host' não existirem, instale:\n"
        "  sudo apt install dnsutils"
    )
)

step("Verificando configuração de proxy...")
add(
    "Configuração de Proxy (sistema)",
    run(
        "netsh winhttp show proxy",
        'echo "http_proxy=$http_proxy"; echo "https_proxy=$https_proxy"; '
        'echo "no_proxy=$no_proxy"; env | grep -i proxy'
    ),
    note=(
        "Mesmo sem proxy configurado no SO, o tráfego pode passar por um\n"
        "PROXY TRANSPARENTE no gateway/firewall (sem nada configurado no PC).\n"
        "Nesse caso este teste não mostra problema algum, mas o bloqueio pode\n"
        "estar acontecendo de qualquer forma."
    )
)

step("Verificando proxy do navegador...")
add(
    "Proxy do Navegador (registro / gsettings)",
    run(
        r'''powershell "Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select ProxyEnable,ProxyServer,AutoConfigURL"''',
        'gsettings get org.gnome.system.proxy mode 2>/dev/null '
        '|| echo "gsettings não disponível (ambiente sem GNOME/GUI)"'
    ),
    note=(
        "'ProxyEnable: 0' ou 'mode: none' = sem proxy manual configurado no\n"
        "navegador. Se 'AutoConfigURL' estiver preenchido, o navegador busca\n"
        "um arquivo .pac que pode rotear o tráfego de forma diferente por\n"
        "domínio/categoria."
    )
)

step("Verificando firewall local...")
add(
    "Firewall Local",
    run(
        "netsh advfirewall show allprofiles",
        'echo ---IPTABLES---; '
        'sudo -n iptables -L -n -v 2>/dev/null '
        '|| echo "iptables requer sudo -> rode: sudo iptables -L -n -v"; '
        'echo ---UFW---; '
        'sudo -n ufw status verbose 2>/dev/null '
        '|| echo "ufw requer sudo -> rode: sudo ufw status verbose"'
    ),
    note=(
        "Mostra o firewall LOCAL do PC, não o firewall da rede corporativa\n"
        "(que normalmente é um appliance separado e não aparece aqui).\n"
        "Se o firewall local estiver 'Desligado'/inativo, ele não é a causa\n"
        "do bloqueio - o problema está em outro lugar da rede."
    )
)

step("Verificando domínio corporativo...")
add(
    "Domínio Corporativo (Active Directory)",
    run(
        'powershell "(Get-CimInstance Win32_ComputerSystem).PartOfDomain"',
        'realm list 2>/dev/null '
        '|| echo "realmd não encontrado/configurado (provavelmente não está em domínio)"'
    ),
    note=(
        "Se 'True' (Windows) ou houver domínio listado (Linux), o PC recebe\n"
        "políticas de TI automaticamente (GPO/SSSD), que podem incluir proxy,\n"
        "DNS e regras de firewall aplicadas sem o usuário perceber."
    )
)

step("Verificando serviços de segurança/EDR...")
add(
    "Serviços de Segurança / EDR em execução",
    run(
        'powershell "Get-Service | Where-Object {$_.DisplayName -match '
        "'forti|crowd|sophos|eset|sentinel|mcafee|symantec|cisco|defender|trend|zscaler|netskope'"
        '} | Format-Table Status,Name,DisplayName -AutoSize"',
        'systemctl list-units --type=service --state=running 2>/dev/null | '
        'grep -Ei "forti|crowd|sophos|eset|sentinel|mcafee|symantec|cisco|clamav|firewalld|zscaler|netskope" '
        '|| echo "Nenhum serviço conhecido encontrado (ou systemctl indisponível)"'
    ),
    note=(
        "Clientes corporativos (Forticlient, Zscaler, Netskope, Cisco\n"
        "Umbrella/AnyConnect, etc.) costumam incluir um filtro de tráfego que\n"
        "roda como serviço/daemon e pode bloquear categorias como 'Games' ou\n"
        "'P2P', MESMO com o firewall do Windows desligado.\n"
        "Se algo aparecer aqui, peça ao TI uma exceção para o PS Remote Play."
    )
)

step("Verificando VPNs e adaptadores de túnel...")
vpn_output = run(
    'powershell "Get-NetAdapter | Where-Object {$_.InterfaceDescription -match '
    "'VPN|TAP|Tunnel|ZeroTier|Tailscale|Radmin|Hamachi|WireGuard' -or "
    "$_.Name -match 'VPN|TAP|Tunnel|ZeroTier|Tailscale|Radmin|Hamachi|WireGuard'"
    '} | Format-Table Name,Status,InterfaceDescription -AutoSize"',
    'ip link show | grep -Ei "tun|tap|wg|vpn|zerotier|tailscale|hamachi" '
    '|| echo "Nenhuma interface de VPN encontrada"; '
    'echo ---NMCLI---; nmcli connection show 2>/dev/null | grep -i vpn'
)

# Detecta adaptadores de VPN/túnel ATIVOS agora, para o diagnóstico automático.
vpn_active_adapters = []
if IS_WINDOWS:
    for line in vpn_output.splitlines():
        parts = line.split()
        if "Up" in parts:
            idx = parts.index("Up")
            name = " ".join(parts[:idx]).strip()
            if name and name.lower() != "name":
                vpn_active_adapters.append(name)
else:
    for line in vpn_output.splitlines():
        if "state UP" in line and ":" in line:
            vpn_active_adapters.append(line.split(":")[1].strip())

add(
    "VPNs e Adaptadores de Túnel",
    vpn_output,
    note=(
        "*** CAUSA JÁ CONFIRMADA EM CASOS REAIS COM PS REMOTE PLAY ***\n"
        "Adaptadores virtuais como ZeroTier, Radmin VPN, Tailscale, Hamachi e\n"
        "WireGuard - mesmo sem estar 'conectados' a um servidor - criam uma\n"
        "interface de rede extra. Vários apps de streaming/P2P (incluindo o\n"
        "PS Remote Play) escolhem a interface de saída diretamente, em vez de\n"
        "confiar só na rota padrão do Windows. Resultado: mesmo a tabela de\n"
        "rotas parecendo normal, o Remote Play pode tentar sair por um desses\n"
        "adaptadores e falhar (não encontra o PS5, ou conecta e cai).\n\n"
        + (
            "Adaptador(es) ATIVO(S) agora: " + ", ".join(vpn_active_adapters) + "\n"
            "-> Estes são os principais suspeitos. Teste o procedimento abaixo.\n\n"
            if vpn_active_adapters else
            "Nenhum desses adaptadores está 'Up' agora. Se isso for verificado\n"
            "em outro momento com algum deles ativo, ele entra como suspeito.\n\n"
        )
        + "TESTE RECOMENDADO (reversível - religa no final):\n"
        "Windows (PowerShell como Administrador):\n"
        "  Get-NetAdapter | Where-Object Status -eq 'Up' | Select Name\n"
        "  Disable-NetAdapter -Name \"<nome do adaptador>\" -Confirm:$false\n"
        "  # ... teste o Remote Play ...\n"
        "  Enable-NetAdapter -Name \"<nome do adaptador>\" -Confirm:$false\n\n"
        "Ou via interface gráfica: 'ncpa.cpl' -> botão direito no adaptador\n"
        "-> Desabilitar / Habilitar.\n\n"
        "Linux: sudo ip link set <interface> down   (e 'up' para religar)\n\n"
        "Se resolver, desabilite Radmin VPN/ZeroTier/Tailscale/etc. sempre que\n"
        "for usar o Remote Play (ou habilite-os só quando precisar deles).\n"
        "Teste um adaptador por vez para descobrir qual deles é o culpado."
    )
)

step("Verificando prioridade de interfaces (métricas de rota)...")
add(
    "Prioridade de Interfaces e Rotas Padrão",
    run(
        'powershell "Get-NetIPInterface -AddressFamily IPv4 | Sort-Object InterfaceMetric '
        '| Format-Table ifIndex,InterfaceAlias,InterfaceMetric,ConnectionState,Dhcp -AutoSize"',
        'ip -4 route show'
    ),
    note=(
        "Quanto MENOR o 'InterfaceMetric' (Windows) ou 'metric' (Linux), MAIOR\n"
        "a prioridade dessa interface para tráfego sem rota mais específica.\n\n"
        "Se um adaptador de VPN/túnel (ZeroTier, Radmin, Tailscale, Hamachi,\n"
        "WireGuard, Teredo) tiver métrica MENOR que a sua placa Ethernet/Wi-Fi\n"
        "real, ele pode 'ganhar' a prioridade de roteamento - mesmo a rota\n"
        "padrão da Ethernet existindo e parecendo correta. Isso é consistente\n"
        "com o problema confirmado na seção 'VPNs e Adaptadores de Túnel'.\n\n"
        "Corrigir sem desabilitar o adaptador (Windows, como Admin):\n"
        "  Set-NetIPInterface -InterfaceAlias \"<nome da VPN>\" -InterfaceMetric 9999\n\n"
        "Linux: aumente a métrica da rota da VPN:\n"
        "  sudo ip route change default via <gw_vpn> dev <iface_vpn> metric 9999"
    )
)

step("Verificando processo do PS Remote Play...")
add(
    "Processo do PS Remote Play",
    run(
        'powershell "Get-Process -Name *RemotePlay* -ErrorAction SilentlyContinue '
        '| Format-Table Id,ProcessName,CPU -AutoSize"',
        'ps aux | grep -i -E "remoteplay|chiaki" | grep -v grep '
        '|| echo "Processo não encontrado"'
    ),
    note=(
        "Se nada aparecer, o app não está aberto agora.\n"
        "DICA: abra o PS Remote Play, clique em 'Conectar' e SÓ ENTÃO rode\n"
        "este script de novo (ou ao menos as seções de 'Endpoints UDP' e\n"
        "'Conexões em Portas do Remote Play' abaixo) para capturar o tráfego\n"
        "no momento exato da tentativa de conexão."
    )
)

step("Testando HTTPS para playstation.com...")
add(
    "Teste HTTPS - www.playstation.com",
    http_status("https://www.playstation.com"),
    note=(
        "'200 OK' = HTTPS básico funciona normalmente até a Sony.\n"
        "'[ERRO SSL]' = possível inspeção SSL corporativa (proxy MITM).\n"
        "'[ERRO DE CONEXÃO] timed out' = pacotes descartados (DROP).\n"
        "'[ERRO DE CONEXÃO] ... getaddrinfo failed' = falha de DNS."
    )
)

step("Testando HTTPS para a CDN do Remote Play...")
add(
    f"Teste HTTPS - {PS_HOST}",
    http_status(f"https://{PS_HOST}"),
    note=(
        "Um '200 OK' aqui confirma HTTPS básico até a CDN da Sony.\n"
        "IMPORTANTE: este host é uma CDN de DOWNLOAD/atualização, não o\n"
        "servidor de streaming do Remote Play. Esse teste passar NÃO\n"
        "garante que o streaming (que usa UDP e outros endereços) funcione."
    )
)

step("Testando portas TCP do Remote Play...")
PS_TCP_PORTS = [443, 9295, 9296, 9297, 9298, 9302, 9303]
port_results = {}
port_lines = []
for port in PS_TCP_PORTS:
    ok, msg = tcp_port_test(PS_HOST, port)
    port_results[port] = (ok, msg)
    status = "OK    " if ok else "FALHOU"
    port_lines.append(f"  {PS_HOST}:{port:<5} [{status}] {msg}")

add(
    "Teste de Portas TCP (Remote Play)",
    "\n".join(port_lines),
    note=(
        "ATENÇÃO sobre este teste:\n"
        f"- '{PS_HOST}' é um host de CDN (download), que normalmente só\n"
        "  atende na porta 443. 'FALHOU' nas portas 9295-9303 contra ESTE\n"
        "  host é ESPERADO e não comprova bloqueio - o servidor de\n"
        "  streaming real do Remote Play usa outros endereços (PSN/relay),\n"
        "  atribuídos dinamicamente durante a conexão.\n"
        "- O dado realmente útil aqui é a porta 443: se ela falhar para\n"
        "  este host (e tiver funcionado em outra rede, ex: sua casa), é\n"
        "  sinal forte de bloqueio/inspeção no caminho desta rede.\n"
        "- 'Timeout' = pacote descartado (DROP) -> indício de firewall.\n"
        "- 'Conexão recusada' = chegou no destino, porta fechada lá\n"
        "  (normal para portas que esse host não usa)."
    )
)

step("Verificando endpoints UDP ativos do Remote Play...")
add(
    "Endpoints UDP Ativos (durante tentativa de conexão)",
    run(
        'powershell "$p = Get-Process -Name *RemotePlay* -ErrorAction SilentlyContinue; '
        "if ($p) { Get-NetUDPEndpoint -OwningProcess $p.Id -ErrorAction SilentlyContinue "
        '| Format-Table LocalAddress,LocalPort,RemoteAddress,RemotePort -AutoSize } '
        "else { 'RemotePlay não está em execução - abra o app, clique em Conectar e rode esta seção novamente.' }\"",
        'ss -u -a -n -p 2>/dev/null | grep -i remoteplay '
        '|| echo "RemotePlay não encontrado, ou \'ss -p\' precisa de sudo: '
        'sudo ss -u -a -n -p | grep -i remoteplay"'
    ),
    note=(
        "ESTE É O TESTE MAIS IMPORTANTE para detectar bloqueio de UDP.\n\n"
        "Como usar corretamente:\n"
        "  1. Abra o PS Remote Play.\n"
        "  2. Clique em 'Conectar'.\n"
        "  3. Enquanto ele tenta conectar (antes de dar erro), rode esta\n"
        "     seção do script (ou o comando equivalente manualmente).\n\n"
        "Interpretação:\n"
        "- Nenhum endpoint UDP para IP externo aparece -> o app não\n"
        "  conseguiu nem ENVIAR pacotes UDP (pode ser DNS/descoberta\n"
        "  falhando antes de abrir o socket).\n"
        "- Aparecem endpoints UDP para IPs externos, mas a conexão falha\n"
        "  -> os pacotes saem do PC, porém são bloqueados/descartados no\n"
        "  caminho (firewall corporativo) ou a resposta não volta.\n\n"
        "Windows: 'Get-NetUDPEndpoint' pode precisar de PowerShell como\n"
        "Administrador para mostrar tudo.\n"
        "Linux: 'ss -p' precisa de privilégio -> rode com 'sudo'."
    )
)

step("Verificando conexões em portas do Remote Play...")
add(
    "Conexões Ativas em Portas do Remote Play",
    run(
        'netstat -ano | findstr ":9295 :9296 :9297 :9298 :9302 :9303 :9304 :9305 :9306 :9307 :9308 :9309"',
        'ss -tunp 2>/dev/null | grep -E ":(9295|9296|9297|9298|930[2-9])" '
        '|| echo "Nenhuma conexão ativa nessas portas agora"'
    ),
    note=(
        "Mostra conexões TCP/UDP ativas nas portas tipicamente usadas pelo\n"
        "PS Remote Play. Para um resultado útil, rode com o Remote Play\n"
        "tentando conectar (igual ao teste de Endpoints UDP acima)."
    )
)

step("Testando ping...")
add(
    "Teste de Ping",
    run(
        f"ping -n 4 {PS_HOST}",
        f"ping -c 4 {PS_HOST}"
    ),
    note=(
        "Ping usa ICMP, protocolo diferente do TCP/UDP usado pelo Remote\n"
        "Play - é possível o ping funcionar e o Remote Play falhar (ou o\n"
        "contrário). Serve para confirmar que existe rota até o host e\n"
        "medir a latência (RTT)."
    )
)

step("Executando traceroute (pode levar até ~1 min)...")
add(
    "Traceroute até a CDN da Sony",
    run(
        f"tracert -h 15 -w 800 {PS_HOST}",
        f"traceroute -m 15 -w 1 {PS_HOST} 2>/dev/null "
        f"|| tracepath -m 15 {PS_HOST} 2>/dev/null "
        f"|| echo 'Instale: sudo apt install traceroute (ou iputils-tracepath)'",
        timeout=60,
    ),
    note=(
        "Mostra cada 'salto' (roteador) até o destino. Se a lista parar de\n"
        "repente em um IP interno (ex: 172.17.x.x, 10.x.x.x), esse é\n"
        "provavelmente o firewall/gateway corporativo - o tráfego não está\n"
        "saindo da rede da empresa.\n"
        "'* * *' numa linha = roteador não respondeu ao ICMP naquele salto\n"
        "(comum e muitas vezes normal). Os limites -h/-m 15 e -w foram\n"
        "reduzidos para não travar 30s+ por salto."
    )
)


# ---------------------------------------------------------------------------
# Diagnóstico automático
# ---------------------------------------------------------------------------

step("Gerando diagnóstico automático...")

https_play = http_status("https://www.playstation.com")
tcp443_ok = port_results.get(443, (False, ""))[0]
https_play_ok = https_play.startswith("200")
https_ssl_error = "[ERRO SSL]" in https_play

LABEL_WIDTH = 40
linhas = []
linhas.append(f"{'PS Remote Play (informado pelo usuário)'.ljust(LABEL_WIDTH)} : {rp_status_text}")
linhas.append(f"{'HTTPS www.playstation.com'.ljust(LABEL_WIDTH)} : {https_play}")
linhas.append(f"{f'TCP 443 ({PS_HOST})'.ljust(LABEL_WIDTH)} : {'OK' if tcp443_ok else 'FALHOU'}")
linhas.append(
    f"{'Adaptadores de VPN/túnel ativos'.ljust(LABEL_WIDTH)} : "
    + (", ".join(vpn_active_adapters) if vpn_active_adapters else "nenhum detectado")
)
linhas.append("")

# 1) Suspeito principal: adaptador de VPN/túnel ativo (causa já confirmada
#    em casos reais com ZeroTier/Radmin VPN/Tailscale).
if vpn_active_adapters:
    linhas.append("=> SUSPEITO PRINCIPAL: adaptador(es) de VPN/túnel ativo(s)")
    linhas.append(f"   ({', '.join(vpn_active_adapters)}).")
    linhas.append("   Esse é o tipo de problema JÁ CONFIRMADO em casos reais (ZeroTier")
    linhas.append("   e/ou Radmin VPN causando falha no PS Remote Play mesmo com toda")
    linhas.append("   a rede 'normal' por fora). Veja as seções 'VPNs e Adaptadores de")
    linhas.append("   Túnel' e 'Prioridade de Interfaces' acima, e teste desabilitar")
    linhas.append("   cada adaptador (um por vez) antes de abrir o Remote Play.")
    linhas.append("")

# 2) Indícios de inspeção SSL.
if https_ssl_error:
    linhas.append("=> Detectado erro de certificado SSL ao acessar a Sony.")
    linhas.append("   Isso indica INSPEÇÃO SSL CORPORATIVA (proxy MITM trocando")
    linhas.append("   certificados). Apps com 'certificate pinning', como o")
    linhas.append("   Remote Play, podem se recusar a conectar nesse cenário.")
    linhas.append("   Solução: solicitar ao TI uma exceção de inspeção SSL")
    linhas.append("   (bypass) para os domínios *.playstation.net / *.sony.com.")
    linhas.append("")
elif https_play_ok and tcp443_ok:
    linhas.append("HTTPS básico funcionando normalmente - não é bloqueio total")
    linhas.append("à PlayStation/Sony. Se o suspeito principal acima não resolver,")
    linhas.append("considere também:")
    linhas.append("")
    linhas.append("- Bloqueio/filtragem de UDP: o Remote Play depende de UDP para")
    linhas.append("  streaming de video/audio. Firewalls corporativos costumam")
    linhas.append("  permitir HTTPS (443/TCP) mas restringir UDP genérico.")
    linhas.append("  -> Veja 'Endpoints UDP Ativos' (rode durante uma tentativa de")
    linhas.append("     conexão). Solução: pedir ao TI liberação de UDP para os")
    linhas.append("     domínios/IPs da Sony, ou testar em outra rede (4G/hotspot).")
    linhas.append("")
    linhas.append("- Categoria 'Games'/'Streaming'/'P2P' bloqueada no firewall/EDR")
    linhas.append("  (Fortigate, Palo Alto, Cisco Umbrella, Zscaler, Netskope, etc.)")
    linhas.append("  -> Veja 'Serviços de Segurança / EDR'. Solução: pedir ao TI")
    linhas.append("     exceção para a categoria 'Gaming' ou para os domínios/IPs")
    linhas.append("     do PS Remote Play.")
    linhas.append("")
else:
    linhas.append("Já há indícios de bloqueio mesmo para HTTPS básico.")
    linhas.append("Revise as seções 'DNS', 'Proxy' e 'Firewall Local' acima - o")
    linhas.append("problema pode não ser específico do Remote Play, e sim de toda")
    linhas.append("a conectividade à internet nesta rede.")
    linhas.append("")

# 3) Cruza com o que o usuário observou no app.
if rp_ok == "n" and rp_detail == "b":
    linhas.append("Observação: o PS5 NUNCA apareceu na lista de consoles. A descoberta")
    linhas.append("usa broadcast/multicast UDP na rede LOCAL - é fortemente afetada por")
    linhas.append("adaptadores de VPN ativos (reforça o suspeito principal acima),")
    linhas.append("estar em VLAN diferente da do PS5, ou isolamento de cliente no Wi-Fi.")
elif rp_ok == "n" and rp_detail == "a":
    linhas.append("Observação: o PS5 apareceu na lista, mas a conexão falhou depois -")
    linhas.append("a descoberta local funcionou; o problema está na fase de streaming")
    linhas.append("(dados), mais associada a bloqueio de firewall/UDP corporativo do")
    linhas.append("que a roteamento local.")
elif rp_ok == "s":
    linhas.append("=> CONCLUSÃO: nesta rede o PS Remote Play está FUNCIONANDO e nenhum")
    linhas.append("   bloqueio crítico foi detectado. Guarde este relatório como")
    linhas.append("   REFERÊNCIA/CONTROLE para comparar com redes onde o Remote Play")
    linhas.append("   falha (ex: anexe-o ao chamado de TI da rede corporativa).")

add("Diagnóstico Automático (resumo)", "\n".join(linhas))


# ---------------------------------------------------------------------------
# Salvar relatório
# ---------------------------------------------------------------------------

OUTPUT_FILE = "remoteplay_diagnostico.txt"
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(REPORT))

print("\nRelatório salvo em:")
print(os.path.abspath(OUTPUT_FILE))
