# PS Remote Play - Diagnóstico de Rede

Script de diagnóstico (Windows e Linux) para investigar por que o **PS Remote
Play** (PS4/PS5) não conecta em uma determinada rede - especialmente útil para
comparar uma rede "boa" (ex: casa) com uma rede "problemática" (ex: empresa).

Ele coleta informações de sistema, rede, DNS, proxy, firewall, VPN/adaptadores
de túnel e conectividade, e gera um relatório único em texto explicando o que
cada resultado significa e o que fazer em caso de erro.

## Requisitos

- Python 3.8+ (usa apenas a biblioteca padrão - sem `pip install`)
- Windows 10/11 ou Linux

## Como executar

### Windows

```powershell
python script.py
```

ou clique duas vezes / `py script.py`. De preferência abra o PowerShell como
**Administrador** - isso ajuda a seção de Endpoints UDP a mostrar mais
detalhes.

### Linux

```bash
python3 script.py
```

Algumas seções (iptables, `ss -p`) precisam de privilégio. Se aparecer
"requer sudo" no relatório, rode novamente com:

```bash
sudo python3 script.py
```

Se algum comando não for encontrado, instale os pacotes básicos:

```bash
sudo apt update && sudo apt install -y iproute2 dnsutils net-tools \
     traceroute iputils-ping curl
```

## O que o script pergunta

Antes de coletar os dados, ele pergunta sobre a **última tentativa** de uso do
PS Remote Play nesta rede:

- Se conectou com sucesso ou não;
- Em caso de falha, se o PS5 chegou a **aparecer na lista de consoles**
  (problema na descoberta local) ou **nunca apareceu** (problema na fase de
  streaming/dados).

Essas respostas ficam registradas no relatório, tanto para casos de falha
quanto para servir como **referência/controle** quando tudo funciona (útil
para comparar depois com uma rede onde o Remote Play falha).

Pressione Enter para pular qualquer pergunta.

## O que é coletado

- IP público e configuração de rede (`ipconfig` / `ip address`)
- Adaptadores de rede e tabela de rotas
- Resolução DNS para o host do Remote Play
- Configuração de proxy (sistema e navegador)
- Firewall local
- Domínio corporativo (Active Directory / realmd)
- Serviços de segurança/EDR em execução
- **VPNs e adaptadores de túnel** (ZeroTier, Radmin VPN, Tailscale, Hamachi,
  WireGuard, etc.) e prioridade de interfaces/métricas de rota
- Processo do PS Remote Play e endpoints UDP/TCP ativos
- Testes de portas TCP, ping e traceroute até a CDN da Sony
- Um **resumo automático** com o diagnóstico mais provável

Cada seção do relatório vem com um bloco **"Como interpretar / o que fazer"**
explicando o significado do resultado e como corrigir problemas comuns.

## Causa já confirmada (VPNs/adaptadores virtuais)

Em casos reais, adaptadores virtuais como **ZeroTier**, **Radmin VPN** e
**Tailscale** - mesmo sem estar conectados a um servidor - podem fazer o PS
Remote Play escolher a interface de rede errada (descoberta do PS5 falha ou a
conexão cai). Se a seção "VPNs e Adaptadores de Túnel" do relatório indicar
algum adaptador ativo, esse é o primeiro suspeito: teste desabilitá-lo (um por
vez) e tentar o Remote Play novamente.

## Saída

Gera o arquivo `remoteplay_diagnostico.txt` (UTF-8) na mesma pasta do script.

> **Atenção:** esse arquivo contém dados de rede do seu PC (IP público,
> endereços locais, nome do host, rotas, etc.). Revise antes de compartilhar
> com terceiros (ex: suporte/TI). Por isso ele está no `.gitignore` e não é
> versionado.
