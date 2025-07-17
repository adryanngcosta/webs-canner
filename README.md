# 🔴 Web Vulnerability Scanner - Red Team Tool

Uma ferramenta avançada de red team para detecção de vulnerabilidades em ambientes web, desenvolvida em Python com múltiplas funcionalidades de segurança.

## 🚀 Características

### Scanner Principal (`web_scanner.py`)
- **Scan DNS**: Verificação de registros A, MX, TXT
- **Scan de Portas**: Detecção de portas abertas com Nmap
- **Verificação SSL/TLS**: Análise de certificados e configurações
- **Headers de Segurança**: Verificação de headers de proteção
- **Directory Traversal**: Teste de vulnerabilidades de path traversal
- **SQL Injection**: Detecção de vulnerabilidades SQL
- **Cross-Site Scripting (XSS)**: Teste de vulnerabilidades XSS
- **Open Redirect**: Verificação de redirecionamentos abertos
- **Arquivos Sensíveis**: Verificação de arquivos comuns sensíveis
- **Listagem de Diretórios**: Detecção de listagem de diretórios
- **Robots.txt**: Análise do arquivo robots.txt
- **Sitemap**: Verificação do sitemap.xml

### Scanner Avançado (`advanced_scanner.py`)
- **Descoberta de Subdomínios**: Scan de subdomínios comuns
- **Detecção de Tecnologias**: Identificação de tecnologias web
- **Vulnerabilidades SSL/TLS**: Análise de versões e cipher suites
- **Métodos HTTP**: Teste de métodos HTTP permitidos
- **Vazamento de Informações**: Detecção de informações sensíveis
- **Configuração CORS**: Verificação de configurações CORS
- **Clickjacking**: Teste de proteção contra clickjacking
- **SSRF**: Análise de potencial para Server-Side Request Forgery

### Automação (`red_team_automation.py`)
- **Integração com Ferramentas**: Nmap, Dirb, Nikto, SQLMap, Nuclei
- **Execução Automatizada**: Orquestração de múltiplas ferramentas
- **Relatórios Consolidados**: Geração de relatórios unificados
- **Verificação de Dependências**: Checagem de ferramentas instaladas

## 📋 Pré-requisitos

### Sistema Operacional
- Linux (recomendado: Kali Linux, Ubuntu)
- macOS
- Windows (com WSL)

### Python
- Python 3.7 ou superior

### Ferramentas Externas (Opcionais)
```bash
# Kali Linux / Ubuntu
sudo apt update
sudo apt install nmap dirb nikto sqlmap nuclei

# macOS
brew install nmap
# Instalar outras ferramentas via pip ou download manual
```

## 🛠️ Instalação

1. **Clone o repositório**
```bash
git clone <repository-url>
cd web-scanner
```

2. **Instale as dependências Python**
```bash
pip3 install -r requirements.txt
```

3. **Verifique as ferramentas externas**
```bash
python3 red_team_automation.py --check-tools
```

4. **Configure permissões de execução**
```bash
chmod +x web_scanner.py
chmod +x advanced_scanner.py
chmod +x red_team_automation.py
```

## 🎯 Como Usar

### Scanner Principal
```bash
# Scan básico
python3 web_scanner.py https://example.com

# Scan verboso
python3 web_scanner.py https://example.com --verbose

# Scan com múltiplas threads
python3 web_scanner.py https://example.com --threads 20
```

### Scanner Avançado
```bash
# Scan avançado completo
python3 advanced_scanner.py https://example.com
```

### Automação Completa
```bash
# Automação com todas as ferramentas
python3 red_team_automation.py https://example.com

# Automação com diretório de saída personalizado
python3 red_team_automation.py https://example.com --output-dir ./my_reports
```

## 📊 Exemplos de Saída

### Scanner Principal
```
╔══════════════════════════════════════════════════════════════╗
║                    WEB VULNERABILITY SCANNER                    ║
║                        RED TEAM TOOL                            ║
╚══════════════════════════════════════════════════════════════╝

Target: https://example.com
Scanner iniciado em: 2024-01-15 14:30:25

[14:30:25] INFO: Iniciando scan DNS...
[14:30:26] SUCCESS: Registros A encontrados: ['93.184.216.34']
[14:30:27] INFO: Iniciando scan de portas...
[14:30:28] SUCCESS: Porta 80/tcp (http) está aberta
[14:30:29] SUCCESS: Porta 443/tcp (https) está aberta
[14:30:30] CRITICAL: Vulnerabilidade encontrada: Missing Security Header: X-Frame-Options - MEDIUM
```

### Relatório Final
```
══════════════════════════════════════════════════════════════
                    RELATÓRIO FINAL
══════════════════════════════════════════════════════════════

Target: https://example.com
Data do Scan: 2024-01-15 14:35:42
Portas Abertas: 80, 443

Vulnerabilidades Encontradas: 5
  • Críticas: 1
  • Altas: 2
  • Médias: 2
  • Baixas: 0

Detalhes das Vulnerabilidades:

[1] SQL Injection (CRITICAL)
    Descrição: Possível vulnerabilidade de SQL Injection no parâmetro id
    Evidência: Payload: ' OR '1'='1, Parâmetro: id, Erro: sql syntax

[2] Missing Security Header: X-Frame-Options (MEDIUM)
    Descrição: Header de segurança ausente: Clickjacking protection
    Evidência: Header esperado: X-Frame-Options
```

## 🔧 Configuração Avançada

### Personalização de Payloads
Edite os arquivos `web_scanner.py` e `advanced_scanner.py` para adicionar ou modificar payloads de teste:

```python
# Em web_scanner.py
sql_payloads = [
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    # Adicione seus próprios payloads aqui
]

xss_payloads = [
    "<script>alert('XSS')</script>",
    # Adicione seus próprios payloads aqui
]
```

### Configuração de Threads
Ajuste o número de threads para otimizar performance:

```bash
python3 web_scanner.py https://example.com --threads 50
```

### Timeouts Personalizados
Modifique os timeouts nos arquivos para ambientes lentos:

```python
# Aumentar timeout para redes lentas
response = self.session.get(test_url, timeout=15)
```

## 📁 Estrutura de Arquivos

```
web-scanner/
├── web_scanner.py              # Scanner principal
├── advanced_scanner.py         # Scanner avançado
├── red_team_automation.py      # Automação completa
├── requirements.txt            # Dependências Python
├── README.md                   # Documentação
└── reports/                    # Diretório de relatórios
    ├── scan_report_1234567890.json
    ├── nmap_scan.txt
    ├── dirb_scan.txt
    ├── nikto_scan.txt
    └── red_team_summary.json
```

## 🛡️ Considerações de Segurança

### Uso Ético
- **Use apenas em sistemas que você possui ou tem autorização explícita**
- **Respeite as políticas de segurança da organização**
- **Não execute em sistemas de produção sem autorização**
- **Documente todas as atividades de teste**

### Proteção Legal
- Este software é fornecido "como está" sem garantias
- O usuário é responsável por seu uso adequado
- Sempre obtenha autorização por escrito antes de testar sistemas

### Boas Práticas
- Execute em ambiente controlado primeiro
- Faça backup dos dados antes dos testes
- Monitore o impacto nos sistemas
- Documente todas as vulnerabilidades encontradas

## 🐛 Solução de Problemas

### Erro: "Module not found"
```bash
pip3 install -r requirements.txt
```

### Erro: "Permission denied"
```bash
chmod +x *.py
```

### Ferramentas externas não encontradas
```bash
# Verificar instalação
python3 red_team_automation.py --check-tools

# Instalar ferramentas faltantes
sudo apt install nmap dirb nikto
pip3 install sqlmap nuclei
```

### Timeout em redes lentas
Edite os arquivos e aumente os timeouts:
```python
timeout=30  # Aumentar de 5-10 para 30 segundos
```

## 🤝 Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📝 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## ⚠️ Aviso Legal

**ATENÇÃO**: Esta ferramenta é destinada apenas para fins educacionais e de teste de penetração autorizado. O uso desta ferramenta para atacar sistemas sem autorização explícita é ilegal e pode resultar em consequências legais severas.

O desenvolvedor não se responsabiliza pelo uso inadequado desta ferramenta. Use com responsabilidade e sempre obtenha autorização adequada antes de testar qualquer sistema.

## 📞 Suporte

Para suporte, dúvidas ou sugestões:
- Abra uma issue no GitHub
- Consulte a documentação
- Verifique os logs de erro

---

**Desenvolvido com ❤️ para a comunidade de segurança** 