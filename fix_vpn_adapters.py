#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Correção automática: VPNs/adaptadores de túnel atrapalhando o PS Remote Play
=============================================================================

Detecta e desliga adaptadores de rede virtuais conhecidos por interferir na
descoberta local do PS5 pelo PS Remote Play (ZeroTier, Radmin VPN, Tailscale,
Hamachi, WireGuard, TAP/TUN genéricos) - mesma causa documentada na seção
"VPNs e Adaptadores de Túnel" de script.py, e já confirmada em produção
(ver README.md).

Alguns desses adaptadores (ex: ZeroTier) são mantidos "Up" por um SERVIÇO em
segundo plano - só desabilitar o adaptador não resolve, porque o serviço
reativa a interface sozinho. Este script cuida dos dois: adaptador E serviço.

O que o script faz
-------------------
1. Detecta adaptadores de rede ATIVOS que batem com o padrão de VPN/túnel.
2. Detecta serviços (Windows) / unidades systemd (Linux) relacionados.
3. Mostra o que vai mudar e pede confirmação (a menos que use --yes).
4. Desliga o(s) adaptador(es) e para + desabilita o(s) serviço(s).
5. Salva o estado anterior em 'vpn_fix_state.json' (mesma pasta do script),
   para permitir reverter tudo depois com --restore.

Uso
---
    python fix_vpn_adapters.py            Detecta, mostra e pede confirmação
    python fix_vpn_adapters.py --yes      Aplica sem perguntar
    python fix_vpn_adapters.py --list     Só lista, não mexe em nada
    python fix_vpn_adapters.py --dry-run  Mostra o que faria, sem aplicar
    python fix_vpn_adapters.py --restore  Desfaz (religa adaptadores/serviços)

Requer administrador (Windows) / root (Linux). No Windows, o script tenta se
reabrir elevado (prompt do UAC) automaticamente quando necessário.
"""

import argparse
import ctypes
import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime

IS_WINDOWS = platform.system() == "Windows"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(SCRIPT_DIR, "vpn_fix_state.json")

if IS_WINDOWS:
    try:
        os.system("chcp 65001 >nul")
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Baseado no padrão usado em script.py ("VPNs e Adaptadores de Túnel"), mas com
# \b (word boundary) em VPN/TAP/Tunnel: sem isso, "TAP" batia por substring em
# serviços do Windows sem nenhuma relação (ex: "TapiSrv", "XboxNetApiSvc",
# "EntAppSvc" contêm "tap"/"Tap" no meio do nome). Como este script DESLIGA
# serviços, precisão aqui importa mais do que no script.py (só leitura).
# Nomes de marca (ZeroTier, Tailscale, Radmin, Hamachi, WireGuard) continuam
# como substring normal - baixo risco de colisão com outro software.
VPN_PATTERN = r"\bVPN\b|\bTAP\b|\bTunnel\b|ZeroTier|Tailscale|Radmin|Hamachi|WireGuard"

ALLOWED_START_TYPES = {"Automatic", "Manual", "Disabled", "AutomaticDelayedStart"}


# ---------------------------------------------------------------------------
# Privilégios
# ---------------------------------------------------------------------------

def is_admin():
    if not IS_WINDOWS:
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate_and_exit(extra_args=None):
    """Reabre este script como Administrador (Windows) via UAC e encerra o atual.

    extra_args: argumentos a acrescentar (ex: ["--yes"]) para não pedir a
    mesma confirmação de novo na janela elevada, já que o usuário confirmou
    aqui antes de precisarmos elevar.
    """
    argv = sys.argv + (extra_args or [])
    params = subprocess.list2cmdline(argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    sys.exit(0)


# ---------------------------------------------------------------------------
# Windows: PowerShell helpers
# ---------------------------------------------------------------------------

def _powershell(command, timeout=30):
    # Força a saída do PowerShell para UTF-8 explicitamente: sem isso, a
    # decodificação varia com a codepage OEM do sistema (ex: cp850/cp1252 no
    # Brasil) e acentos saem quebrados ("Servi‡o" em vez de "Serviço").
    full_command = (
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; " + command
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", full_command],
        capture_output=True, timeout=timeout,
    )
    result.stdout = result.stdout.decode("utf-8", errors="replace")
    result.stderr = result.stderr.decode("utf-8", errors="replace")
    return result


def _powershell_json(command, timeout=30):
    out = _powershell(command, timeout).stdout.strip()
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        return [data]
    return data or []


def detect_adapters_windows(only_active=True):
    filtro = f"$_.InterfaceDescription -match '{VPN_PATTERN}' -or $_.Name -match '{VPN_PATTERN}'"
    cmd = (
        f"Get-NetAdapter | Where-Object {{{filtro}}} "
        "| Select-Object Name,InterfaceDescription,Status "
        "| ConvertTo-Json -Compress"
    )
    adapters = _powershell_json(cmd)
    if only_active:
        adapters = [a for a in adapters if a.get("Status") == "Up"]
    return adapters


def detect_services_windows():
    # Status/StartType são enums - sem .ToString(), ConvertTo-Json serializa
    # como número (ex: Status 1, StartType 4) em vez de "Stopped"/"Disabled".
    # Isso quebraria o --restore (Set-Service -StartupType não aceita número).
    filtro = f"$_.DisplayName -match '{VPN_PATTERN}' -or $_.Name -match '{VPN_PATTERN}'"
    cmd = (
        f"Get-Service | Where-Object {{{filtro}}} "
        "| Select-Object Name,DisplayName,"
        "@{N='Status';E={$_.Status.ToString()}},"
        "@{N='StartType';E={$_.StartType.ToString()}} "
        "| ConvertTo-Json -Compress"
    )
    return _powershell_json(cmd)


def apply_windows(adapters, services, dry_run=False):
    changes = {"adapters": [], "services": []}

    for a in adapters:
        name = a["Name"]
        print(f"  -> Desabilitando adaptador '{name}' ...")
        if not dry_run:
            _powershell(f'Disable-NetAdapter -Name "{name}" -Confirm:$false')
        changes["adapters"].append({"Name": name, "PreviousStatus": a.get("Status", "Up")})

    for s in services:
        name = s["Name"]
        prev_start = s.get("StartType") or "Automatic"
        prev_status = s.get("Status") or "Running"
        print(f"  -> Parando e desabilitando serviço '{name}' (era {prev_start}/{prev_status}) ...")
        if not dry_run:
            _powershell(f'Stop-Service -Name "{name}" -Force -ErrorAction SilentlyContinue')
            _powershell(f'Set-Service -Name "{name}" -StartupType Disabled')
        changes["services"].append({
            "Name": name, "PreviousStartType": prev_start, "PreviousStatus": prev_status,
        })

    return changes


def restore_windows(state):
    for a in state.get("adapters", []):
        name = a["Name"]
        print(f"  -> Reativando adaptador '{name}' ...")
        _powershell(f'Enable-NetAdapter -Name "{name}" -Confirm:$false')

    for s in state.get("services", []):
        name = s["Name"]
        prev_start = s.get("PreviousStartType", "Automatic")
        if prev_start not in ALLOWED_START_TYPES:
            prev_start = "Manual"
        prev_status = s.get("PreviousStatus", "Running")
        print(f"  -> Restaurando serviço '{name}' para inicialização '{prev_start}' ...")
        _powershell(f'Set-Service -Name "{name}" -StartupType {prev_start}')
        if prev_status == "Running":
            _powershell(f'Start-Service -Name "{name}" -ErrorAction SilentlyContinue')


# ---------------------------------------------------------------------------
# Linux: ip / systemctl helpers
# ---------------------------------------------------------------------------

def _sh(cmd, timeout=30):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)


def detect_adapters_linux(only_active=True):
    result = _sh("ip -o link show")
    pattern = re.compile(VPN_PATTERN, re.IGNORECASE)
    adapters = []
    for line in result.stdout.splitlines():
        parts = line.split(":", 2)
        if len(parts) < 2:
            continue
        name = parts[1].strip().split("@")[0]
        flags = line.split("<", 1)[1].split(">", 1)[0] if "<" in line else ""
        is_up = "UP" in flags.split(",")
        if pattern.search(name) and (not only_active or is_up):
            adapters.append({"Name": name, "Status": "Up" if is_up else "Down"})
    return adapters


def detect_services_linux():
    result = _sh(
        "systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null"
    )
    pattern = re.compile(VPN_PATTERN, re.IGNORECASE)
    services = []
    for line in result.stdout.splitlines():
        cols = line.split()
        if not cols:
            continue
        unit = cols[0]
        if not pattern.search(unit):
            continue
        active_state = cols[2] if len(cols) > 2 else "unknown"
        services.append({"Name": unit, "Status": active_state})
    return services


def apply_linux(adapters, services, dry_run=False):
    changes = {"adapters": [], "services": []}

    for a in adapters:
        name = a["Name"]
        print(f"  -> Desligando interface '{name}' ...")
        if not dry_run:
            _sh(f"sudo ip link set {name} down")
        changes["adapters"].append({"Name": name, "PreviousStatus": a.get("Status", "Up")})

    for s in services:
        name = s["Name"]
        prev_status = s.get("Status", "active")
        print(f"  -> Parando e desabilitando serviço '{name}' (era {prev_status}) ...")
        if not dry_run:
            _sh(f"sudo systemctl stop {name}")
            _sh(f"sudo systemctl disable {name}")
        changes["services"].append({"Name": name, "PreviousStatus": prev_status})

    return changes


def restore_linux(state):
    for a in state.get("adapters", []):
        name = a["Name"]
        print(f"  -> Religando interface '{name}' ...")
        _sh(f"sudo ip link set {name} up")

    for s in state.get("services", []):
        name = s["Name"]
        prev_status = s.get("PreviousStatus", "active")
        print(f"  -> Restaurando serviço '{name}' ...")
        _sh(f"sudo systemctl enable {name}")
        if prev_status == "active":
            _sh(f"sudo systemctl start {name}")


# ---------------------------------------------------------------------------
# Estado (para permitir reverter depois)
# ---------------------------------------------------------------------------

def load_state():
    if not os.path.exists(STATE_FILE):
        return {"adapters": [], "services": []}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"adapters": [], "services": []}


def save_state(new_changes):
    state = load_state()
    state["timestamp"] = datetime.now().isoformat()

    for key in ("adapters", "services"):
        existing = {item["Name"]: item for item in state.get(key, [])}
        for item in new_changes.get(key, []):
            existing[item["Name"]] = item
        state[key] = list(existing.values())

    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def clear_state():
    if os.path.exists(STATE_FILE):
        os.remove(STATE_FILE)


# ---------------------------------------------------------------------------
# Impressão
# ---------------------------------------------------------------------------

def print_summary(adapters, services):
    if not adapters and not services:
        print("Nenhum adaptador ou serviço de VPN/túnel suspeito foi encontrado ativo.")
        return False

    if adapters:
        print("\nAdaptadores de rede ATIVOS que batem com o padrão de VPN/túnel:")
        for a in adapters:
            desc = a.get("InterfaceDescription", "")
            print(f"  - {a['Name']}" + (f"  ({desc})" if desc else ""))

    if services:
        print("\nServiços relacionados encontrados:")
        for s in services:
            display = s.get("DisplayName", s["Name"])
            status = s.get("Status", "?")
            print(f"  - {s['Name']} [{display}] - status atual: {status}")

    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Detecta e desliga VPNs/adaptadores de túnel que atrapalham o PS Remote Play."
    )
    parser.add_argument("--list", action="store_true", help="Só lista, não aplica nenhuma mudança.")
    parser.add_argument("--yes", "-y", action="store_true", help="Aplica sem pedir confirmação.")
    parser.add_argument("--dry-run", action="store_true", help="Mostra o que faria, sem aplicar.")
    parser.add_argument("--restore", action="store_true", help="Reverte a última correção aplicada.")
    args = parser.parse_args()

    print(f"Sistema: {platform.system()} | Administrador/root: {is_admin()}\n")

    def require_privilege(extra_args=None):
        """Só eleva/exige admin no momento em que uma mudança real vai acontecer -
        evita prompt de UAC quando --list/--dry-run ou quando não há nada a corrigir."""
        if is_admin():
            return
        if IS_WINDOWS:
            print("Esta ação precisa ser Administrador. Reabrindo com elevação (UAC)...")
            elevate_and_exit(extra_args)
        else:
            print("Esta ação precisa de root. Rode novamente com: sudo python3 fix_vpn_adapters.py")
            sys.exit(1)

    if args.restore:
        state = load_state()
        if not state.get("adapters") and not state.get("services"):
            print("Nada para reverter - nenhum 'vpn_fix_state.json' encontrado (ou já vazio).")
            return
        require_privilege()
        print("Revertendo a última correção aplicada...")
        if IS_WINDOWS:
            restore_windows(state)
        else:
            restore_linux(state)
        clear_state()
        print("\nConcluído. Adaptadores/serviços restaurados ao estado anterior.")
        print("Teste o PS Remote Play normalmente com a VPN de volta, se precisar dela para outra coisa.")
        return

    only_active = not args.list
    if IS_WINDOWS:
        adapters = detect_adapters_windows(only_active=only_active)
        services = detect_services_windows()
    else:
        adapters = detect_adapters_linux(only_active=only_active)
        services = detect_services_linux()

    found = print_summary(adapters, services)

    if args.list:
        return

    if not found:
        return

    print(
        "\n*** Estes adaptadores/serviços são a causa já confirmada de falha na descoberta"
        "\ndo PS5 pelo PS Remote Play (ver README.md, seção 'Causas conhecidas'). ***"
    )

    if not args.dry_run and not args.yes:
        resp = input("\nDesligar tudo isso agora? [s/N]: ").strip().lower()
        if resp not in ("s", "sim", "y", "yes"):
            print("Cancelado - nada foi alterado.")
            return

    if not args.dry_run:
        require_privilege(extra_args=["--yes"])

    print("\nAplicando correção..." if not args.dry_run else "\nSimulação (--dry-run), nada será alterado:")
    if IS_WINDOWS:
        changes = apply_windows(adapters, services, dry_run=args.dry_run)
    else:
        changes = apply_linux(adapters, services, dry_run=args.dry_run)

    if not args.dry_run:
        save_state(changes)
        print(f"\nConcluído. Estado anterior salvo em: {STATE_FILE}")
        print("Teste o PS Remote Play agora.")
        print("Para reverter tudo: python fix_vpn_adapters.py --restore")


if __name__ == "__main__":
    main()
