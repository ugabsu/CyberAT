# CyberAT

# 🛡️ CyberSecurity Tips & Best Practices

Bem-vindo ao repositório **CyberSecurity Tips & Best Practices**! Este projeto tem como objetivo reunir as melhores dicas, boas práticas e recomendações sobre segurança da informação, tanto para iniciantes quanto para profissionais experientes.

> 💡 _"Segurança não é um produto, é um processo."_ — Bruce Schneier

---

## 📚 Índice

- [🔐 Fundamentos](#-fundamentos)
- [💻 Segurança em Sistemas Operacionais](#-segurança-em-sistemas-operacionais)
- [🌐 Segurança na Web](#-segurança-na-web)
- [📱 Segurança em Dispositivos Móveis](#-segurança-em-dispositivos-móveis)
- [🧰 Ferramentas Recomendadas](#-ferramentas-recomendadas)
- [📦 Dicas para Devs & DevOps](#-dicas-para-devs--devops)
- [📖 Leituras e Cursos](#-leituras-e-cursos)
- [📜 Licença](#-licença)

---

## 🔐 Fundamentos

Esses são os pilares essenciais da segurança cibernética:

- **Confidencialidade**: Garantir que apenas as pessoas autorizadas tenham acesso às informações.
- **Integridade**: Proteger os dados contra alterações não autorizadas.
- **Disponibilidade**: Assegurar que sistemas e dados estejam disponíveis quando necessário.

### Dicas Essenciais

- Use **autenticação de dois fatores (2FA)** sempre que possível.
- Nunca reutilize senhas. Use **gerenciadores de senhas** (ex: Bitwarden, KeePass).
- Atualize seu sistema operacional e aplicativos com regularidade.
- Suspeite de **links e anexos** em e-mails, mesmo de remetentes conhecidos.
- Faça backup frequente dos seus dados (3-2-1: 3 cópias, 2 mídias, 1 fora do local).
- Evite redes Wi-Fi públicas sem VPN.
- Use senhas fortes, com pelo menos 12 caracteres (incluindo letras, números e símbolos).

---

## 💻 Segurança em Sistemas Operacionais

### Windows

- Ative o **Windows Defender** e mantenha o firewall ativo.
- Desative serviços e portas desnecessárias com `services.msc` e `netstat`.
- Use a política de conta para bloquear usuários após tentativas de login falhas.

### Linux

- Use `ufw` ou `iptables` para configurar um firewall básico.
- Monitore acessos com `fail2ban`, `auditd`, ou `logwatch`.
- Execute serviços como usuários com permissões mínimas (princípio do menor privilégio).
- Mantenha o `sudo` restrito e registre logs de acesso.

---

## 🌐 Segurança na Web

- **HTTPS sempre**: Sites e APIs devem usar certificados válidos.
- Evite vulnerabilidades OWASP Top 10:
  - Injeção (SQL, XSS, etc.)
  - Autenticação quebrada
  - Exposição de dados sensíveis
  - Configuração de segurança incorreta
- Use headers de segurança:
  - `Content-Security-Policy`
  - `Strict-Transport-Security`
  - `X-Frame-Options`
- Faça **pentests periódicos** com ferramentas como OWASP ZAP ou Burp Suite.

---

## 📱 Segurança em Dispositivos Móveis

- Mantenha o sistema e apps atualizados.
- Instale apps apenas de lojas oficiais (Google Play, App Store).
- Cuidado com permissões excessivas de aplicativos.
- Use biometria e senha para bloqueio de tela.
- Evite fazer root/jailbreak, pois compromete a segurança do dispositivo.

---

## 🧰 Ferramentas Recomendadas

| Categoria           | Ferramenta          | Descrição |
|--------------------|---------------------|-----------|
| Password Manager   | Bitwarden, KeePass  | Armazena e gera senhas seguras |
| VPN                | ProtonVPN, Mullvad  | Protege sua conexão em redes públicas |
| Análise de Malware | VirusTotal, Any.run | Verifica arquivos suspeitos |
| Pentest            | Nmap, Wireshark, ZAP, Metasploit | Testes de segurança e análise |
| Firewall pessoal   | SimpleWall, OpenSnitch (Linux) | Monitoramento de conexões |
| Monitoramento      | Wazuh, OSSEC         | SIEM e alertas de segurança |

---

## 📦 Dicas para Devs & DevOps

- **Nunca exponha secrets** (senhas, chaves) em repositórios Git.
  - Use `.gitignore` para esconder arquivos sensíveis.
  - Use `git-secrets` ou `truffleHog` para escanear seus commits.
- Armazene variáveis sensíveis em **cofres de segredos**:
  - Vault by HashiCorp, AWS Secrets Manager, etc.
- Automatize scans com ferramentas como:
  - Snyk, SonarQube, Checkov, Bandit
- Sempre use **CI/CD pipelines seguros** com validação de código.

---

## 📖 Leituras e Cursos

### Livros

- 📘 *The Web Application Hacker's Handbook*
- 📕 *Security Engineering* — Ross Anderson
- 📗 *Cybersecurity for Beginners* — Raef Meeuwisse
- 📙 *Red Team Field Manual (RTFM)*

### Cursos Gratuitos

- [Cybrary](https://www.cybrary.it/)
- [TryHackMe](https://tryhackme.com/)
- [Hack The Box Academy](https://academy.hackthebox.com/)
- [Google IT Support Professional (Coursera)](https://www.coursera.org/professional-certificates/google-it-support)

---

## 📜 Licença

Este repositório está licenciado sob a **MIT License**. Sinta-se livre para contribuir, adaptar e compartilhar.

---

## 🤝 Contribuindo

1. Fork este repositório
2. Crie sua branch: `git checkout -b minha-dica`
3. Faça suas alterações e commit: `git commit -m "Nova dica sobre VPN"`
4. Envie para o repositório remoto: `git push origin minha-dica`
5. Abra um Pull Request

---

## 📬 Contato

Sugestões, dúvidas ou colaborações? Abra uma issue ou mande uma mensagem via [LinkedIn](https://www.linkedin.com/).

---

> Segurança é um jogo sem fim. Mantenha-se curioso, vigilante e atualizado. 🔍🧠💻
