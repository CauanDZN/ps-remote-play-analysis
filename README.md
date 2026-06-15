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
  (problema na descoberta) ou **nunca apareceu** (problema na fase de
  streaming/dados);
- Se o **PS5 está na mesma rede deste PC** ou **em outra rede / Remote Play
  pela internet** (PS5 em casa, este PC em outro lugar) - isso muda
  completamente o diagnóstico, veja abaixo;
- Se este PC já teve o **downgrade + patch de versão 8.5.0.08070** aplicado e
  se isso resolveu.

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
- **PS Remote Play pela Internet** (quando o PS5 está em outra rede): checklist
  de configuração do PS5, status do patch de versão e sugestão do chiaki-ng
- Processo do PS Remote Play e endpoints UDP/TCP ativos
- Testes de portas TCP, ping e traceroute até a CDN da Sony
- Um **resumo automático** com o diagnóstico mais provável

Cada seção do relatório vem com um bloco **"Como interpretar / o que fazer"**
explicando o significado do resultado e como corrigir problemas comuns.

## Causas conhecidas e soluções já testadas

### 1. VPNs/adaptadores virtuais (PS5 na MESMA rede) - CONFIRMADO

Em casos reais, adaptadores virtuais como **ZeroTier**, **Radmin VPN** e
**Tailscale** - mesmo sem estar conectados a um servidor - podem fazer o PS
Remote Play escolher a interface de rede errada (descoberta do PS5 falha ou a
conexão cai). Se a seção "VPNs e Adaptadores de Túnel" do relatório indicar
algum adaptador ativo, esse é o primeiro suspeito: teste desabilitá-lo (um por
vez) e tentar o Remote Play novamente.

**Status:** confirmado no PC de casa - desabilitar Radmin VPN/ZeroTier
resolveu a conexão local.

### 2. Downgrade + patch de versão (PS5 EM OUTRA REDE / pela internet) - CANDIDATO

Quando o PS5 fica em outra rede (ex: PS5 em casa, PC no trabalho), a
"descoberta" não usa broadcast local - depende dos servidores da PSN. Algumas
versões do PS Remote Play (PC), após atualização forçada pela Sony, deixam de
encontrar o PS5 nesse cenário (relatos da comunidade sobre a versão 4508250).

**Workaround:**
1. Desinstale a versão atual do PS Remote Play.
2. Instale a versão **8.5.0.08070**.
3. Use o [remoteplay-version-patcher](https://github.com/xeropresence/remoteplay-version-patcher/releases/)
   (rode como Administrador) para evitar a atualização forçada.
4. Abra o app normalmente e teste a conexão.

**Status:** aplicado no PC de casa como candidato a solução. Ainda precisa ser
testado/confirmado no PC onde o PS5 fica em outra rede (cenário "pela
internet"). O script registra esse status na próxima execução através da
pergunta sobre o patch.

> **Atenção de segurança:** o patcher modifica o `RemotePlay.exe` (binário da
> Sony) e não é assinado/oficial. Baixe de fonte confiável, rode em uma cópia
> e mantenha um backup do instalador original.

### 3. chiaki-ng (ferramenta de diagnóstico/alternativa)

[chiaki-ng](https://github.com/streetpea/chiaki-ng) é um cliente *open source*
de Remote Play que conecta direto ao PS5 via IP + credenciais/registro da
conta, sem depender da lista de dispositivos do app oficial. Se o chiaki-ng
conecta e o app oficial não, o problema é do app/conta na Sony - não da rede.

Para descobrir o IP do PS5 (em casa, na mesma rede dele): no próprio PS5,
**Configurações > Rede > Ver Status da Conexão**, ou veja a lista de
dispositivos conectados (DHCP) no roteador.

## Saída

Gera o arquivo `remoteplay_diagnostico.txt` (UTF-8, com BOM no Windows) na
mesma pasta do script.

> **Atenção:** esse arquivo contém dados de rede do seu PC (IP público,
> endereços locais, nome do host, rotas, etc.). Revise antes de compartilhar
> com terceiros (ex: suporte/TI). Por isso ele está no `.gitignore` e não é
> versionado.

### Acentos estranhos ao abrir o relatório

Se aparecer algo como `ConfiguraÃ§Ã£o` em vez de `Configuração`, é só um
problema de **exibição**, não do arquivo (que já está em UTF-8 correto).
Abra com o Notepad, VS Code, ou no PowerShell rode:

```powershell
Get-Content .\remoteplay_diagnostico.txt -Encoding utf8
```
