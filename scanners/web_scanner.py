#!/usr/bin/env python3
"""
Web Vulnerability Scanner - Red Team Tool
Autor: Red Team Security
Descrição: Ferramenta avançada para detecção de vulnerabilidades em ambientes web
"""

import requests
import argparse
import sys
import time
import json
import re
import socket
import ssl
import dns.resolver
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
import threading
from concurrent.futures import ThreadPoolExecutor
import nmap
import subprocess
import os
import getpass
import logging
import stat
from pathlib import Path
import ipaddress

# Inicializar colorama para cores no terminal
init(autoreset=True)

def is_valid_url(url):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.netloc:
        return False
    return True

def is_private_ip(host):
    try:
        ip = socket.gethostbyname(host)
        return ipaddress.ip_address(ip).is_private or ip.startswith('127.')
    except Exception:
        return False

def is_domain_allowed(domain):
    try:
        with open('allowed_domains.txt') as f:
            allowed = [line.strip().lower() for line in f if line.strip() and not line.startswith('#')]
        return any(domain.endswith(allow) for allow in allowed)
    except Exception:
        return False

# Remover require_password e referências

class WebVulnerabilityScanner:
    def __init__(self, target_url, verbose=False, threads=10):
        if not is_valid_url(target_url):
            print(f"{Fore.RED}URL inválida ou esquema não suportado! Use apenas http(s).{Style.RESET_ALL}")
            sys.exit(1)
        self.target_url = target_url.rstrip('/')
        self.verbose = verbose
        self.threads = min(threads, 50)  # Limite máximo de threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.vulnerabilities = []
        self.ports = []
        self.audit_log_path = "logs/audit.log"
        self.setup_audit_log()
        self.log_audit_event()
        self.ensure_reports_dir()
        
    def print_banner(self):
        """Exibe o banner do scanner"""
        banner = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║                    WEB VULNERABILITY SCANNER                    ║
║                        RED TEAM TOOL                            ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}Target: {self.target_url}
{Fore.CYAN}Scanner iniciado em: {time.strftime('%Y-%m-%d %H:%M:%S')}
{Style.RESET_ALL}
"""
        print(banner)
    
    def log(self, message, level="INFO"):
        """Sistema de logging colorido"""
        colors = {
            "INFO": Fore.BLUE,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "SUCCESS": Fore.GREEN,
            "CRITICAL": Fore.RED + Style.BRIGHT
        }
        color = colors.get(level, Fore.WHITE)
        timestamp = time.strftime('%H:%M:%S')
        print(f"{color}[{timestamp}] {level}: {message}{Style.RESET_ALL}")
    
    def add_vulnerability(self, vuln_type, description, severity, evidence=None):
        """Adiciona uma vulnerabilidade encontrada"""
        vuln = {
            'type': vuln_type,
            'description': description,
            'severity': severity,
            'evidence': evidence,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        self.vulnerabilities.append(vuln)
        self.log(f"Vulnerabilidade encontrada: {vuln_type} - {severity}", "CRITICAL")
    
    def scan_dns(self):
        """Escaneia informações DNS"""
        self.log("Iniciando scan DNS...", "INFO")
        try:
            domain = urlparse(self.target_url).netloc
            resolver = dns.resolver.Resolver()
            
            # Verificar registros A
            try:
                a_records = resolver.resolve(domain, 'A')
                self.log(f"Registros A encontrados: {[str(record) for record in a_records]}", "SUCCESS")
            except Exception as e:
                self.log(f"Erro ao resolver registros A: {e}", "WARNING")
            
            # Verificar registros MX
            try:
                mx_records = resolver.resolve(domain, 'MX')
                self.log(f"Registros MX encontrados: {[str(record) for record in mx_records]}", "SUCCESS")
            except Exception as e:
                self.log(f"Erro ao resolver registros MX: {e}", "WARNING")
            
            # Verificar registros TXT
            try:
                txt_records = resolver.resolve(domain, 'TXT')
                self.log(f"Registros TXT encontrados: {[str(record) for record in txt_records]}", "SUCCESS")
            except Exception as e:
                self.log(f"Erro ao resolver registros TXT: {e}", "WARNING")
                
        except Exception as e:
            self.log(f"Erro no scan DNS: {e}", "ERROR")
    
    def scan_ports(self):
        """Escaneia portas comuns"""
        self.log("Iniciando scan de portas...", "INFO")
        try:
            nm = nmap.PortScanner()
            domain = urlparse(self.target_url).netloc
            
            # Scan das portas mais comuns
            common_ports = "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5900,8080"
            nm.scan(domain, common_ports)
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        state = nm[host][proto][port]['state']
                        service = nm[host][proto][port]['name']
                        if state == 'open':
                            self.ports.append(port)
                            self.log(f"Porta {port}/{proto} ({service}) está aberta", "SUCCESS")
                            
        except Exception as e:
            self.log(f"Erro no scan de portas: {e}", "ERROR")
    
    def check_ssl_certificate(self):
        """Verifica certificado SSL"""
        self.log("Verificando certificado SSL...", "INFO")
        try:
            domain = urlparse(self.target_url).netloc
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Verificar data de expiração
                    not_after = cert['notAfter']
                    self.log(f"Certificado válido até: {not_after}", "SUCCESS")
                    
                    # Verificar se está próximo do vencimento
                    import datetime
                    expiry_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry_date - datetime.datetime.now()).days
                    
                    if days_until_expiry < 30:
                        self.add_vulnerability(
                            "SSL Certificate Expiry",
                            f"Certificado SSL expira em {days_until_expiry} dias",
                            "MEDIUM",
                            f"Expira em: {not_after}"
                        )
                    
                    # Verificar algoritmos de criptografia
                    cipher = ssock.cipher()
                    self.log(f"Cipher suite: {cipher[0]}", "INFO")
                    
        except Exception as e:
            self.log(f"Erro ao verificar SSL: {e}", "ERROR")
    
    def scan_headers(self):
        """Analisa headers de segurança"""
        self.log("Analisando headers de segurança...", "INFO")
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'X-XSS-Protection': 'XSS protection',
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'Referrer-Policy': 'Referrer policy',
                'Permissions-Policy': 'Permissions policy'
            }
            
            missing_headers = []
            for header, description in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
                    self.add_vulnerability(
                        f"Missing Security Header: {header}",
                        f"Header de segurança ausente: {description}",
                        "MEDIUM",
                        f"Header esperado: {header}"
                    )
                else:
                    self.log(f"✓ {header}: {headers[header]}", "SUCCESS")
            
            if missing_headers:
                self.log(f"Headers de segurança ausentes: {', '.join(missing_headers)}", "WARNING")
                
        except Exception as e:
            self.log(f"Erro ao analisar headers: {e}", "ERROR")
    
    def scan_directory_traversal(self):
        """Testa vulnerabilidades de directory traversal"""
        self.log("Testando directory traversal...", "INFO")
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ]
        
        for payload in traversal_payloads:
            try:
                test_url = urljoin(self.target_url, payload)
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'root:' in content or 'administrator' in content:
                        self.add_vulnerability(
                            "Directory Traversal",
                            f"Vulnerabilidade de directory traversal encontrada",
                            "HIGH",
                            f"Payload: {payload}, URL: {test_url}"
                        )
                        break
                        
            except Exception as e:
                if self.verbose:
                    self.log(f"Erro ao testar payload {payload}: {e}", "WARNING")
    
    def scan_sql_injection(self):
        """Testa vulnerabilidades de SQL Injection"""
        self.log("Testando SQL Injection...", "INFO")
        
        sql_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR 1=1#",
            "admin'--"
        ]
        
        # Testar em parâmetros comuns
        test_params = ['id', 'user', 'search', 'q', 'query']
        
        for param in test_params:
            for payload in sql_payloads:
                try:
                    test_url = f"{self.target_url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=5)
                    
                    # Verificar por erros SQL comuns
                    sql_errors = [
                        'sql syntax',
                        'mysql_fetch_array',
                        'oracle error',
                        'postgresql error',
                        'sql server error',
                        'microsoft ole db provider'
                    ]
                    
                    content = response.text.lower()
                    for error in sql_errors:
                        if error in content:
                            self.add_vulnerability(
                                "SQL Injection",
                                f"Possível vulnerabilidade de SQL Injection no parâmetro {param}",
                                "CRITICAL",
                                f"Payload: {payload}, Parâmetro: {param}, Erro: {error}"
                            )
                            break
                            
                except Exception as e:
                    if self.verbose:
                        self.log(f"Erro ao testar SQL injection: {e}", "WARNING")
    
    def scan_xss(self):
        """Testa vulnerabilidades de XSS"""
        self.log("Testando XSS...", "INFO")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>"
        ]
        
        test_params = ['search', 'q', 'query', 'id', 'name']
        
        for param in test_params:
            for payload in xss_payloads:
                try:
                    test_url = f"{self.target_url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=5)
                    
                    # Verificar se o payload foi refletido
                    if payload in response.text:
                        self.add_vulnerability(
                            "Cross-Site Scripting (XSS)",
                            f"Possível vulnerabilidade XSS no parâmetro {param}",
                            "HIGH",
                            f"Payload: {payload}, Parâmetro: {param}"
                        )
                        
                except Exception as e:
                    if self.verbose:
                        self.log(f"Erro ao testar XSS: {e}", "WARNING")
    
    def scan_open_redirect(self):
        """Testa vulnerabilidades de Open Redirect"""
        self.log("Testando Open Redirect...", "INFO")
        
        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "javascript:alert('redirect')",
            "data:text/html,<script>alert('redirect')</script>"
        ]
        
        redirect_params = ['redirect', 'url', 'next', 'target', 'redir']
        
        for param in redirect_params:
            for payload in redirect_payloads:
                try:
                    test_url = f"{self.target_url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=5, allow_redirects=False)
                    
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if payload in location:
                            self.add_vulnerability(
                                "Open Redirect",
                                f"Vulnerabilidade de Open Redirect no parâmetro {param}",
                                "MEDIUM",
                                f"Payload: {payload}, Parâmetro: {param}, Location: {location}"
                            )
                            
                except Exception as e:
                    if self.verbose:
                        self.log(f"Erro ao testar Open Redirect: {e}", "WARNING")
    
    def scan_robots_txt(self):
        """Verifica arquivo robots.txt"""
        self.log("Verificando robots.txt...", "INFO")
        try:
            robots_url = urljoin(self.target_url, '/robots.txt')
            response = self.session.get(robots_url, timeout=5)
            
            if response.status_code == 200:
                self.log("robots.txt encontrado:", "SUCCESS")
                print(response.text)
                
                # Verificar por diretórios sensíveis
                sensitive_dirs = ['admin', 'backup', 'config', 'database', 'logs', 'temp']
                for line in response.text.split('\n'):
                    if line.startswith('Disallow:'):
                        path = line.split(':', 1)[1].strip()
                        for sensitive_dir in sensitive_dirs:
                            if sensitive_dir in path:
                                self.add_vulnerability(
                                    "Sensitive Directory Exposure",
                                    f"Diretório sensível exposto em robots.txt: {path}",
                                    "MEDIUM",
                                    f"Path: {path}"
                                )
            else:
                self.log("robots.txt não encontrado", "INFO")
                
        except Exception as e:
            self.log(f"Erro ao verificar robots.txt: {e}", "ERROR")
    
    def scan_sitemap(self):
        """Verifica sitemap.xml"""
        self.log("Verificando sitemap.xml...", "INFO")
        try:
            sitemap_url = urljoin(self.target_url, '/sitemap.xml')
            response = self.session.get(sitemap_url, timeout=5)
            
            if response.status_code == 200:
                self.log("sitemap.xml encontrado", "SUCCESS")
                # Aqui você pode adicionar análise do conteúdo do sitemap
            else:
                self.log("sitemap.xml não encontrado", "INFO")
                
        except Exception as e:
            self.log(f"Erro ao verificar sitemap.xml: {e}", "ERROR")
    
    def scan_common_files(self):
        """Verifica arquivos comuns"""
        self.log("Verificando arquivos comuns...", "INFO")
        
        common_files = [
            '/.git/config',
            '/.env',
            '/config.php',
            '/wp-config.php',
            '/phpinfo.php',
            '/test.php',
            '/admin.php',
            '/backup.sql',
            '/.htaccess',
            '/web.config'
        ]
        
        for file_path in common_files:
            try:
                test_url = urljoin(self.target_url, file_path)
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    self.add_vulnerability(
                        "Sensitive File Exposure",
                        f"Arquivo sensível acessível: {file_path}",
                        "HIGH",
                        f"URL: {test_url}, Status: {response.status_code}"
                    )
                    
            except Exception as e:
                if self.verbose:
                    self.log(f"Erro ao verificar {file_path}: {e}", "WARNING")
    
    def scan_common_directories(self):
        """Verifica diretórios comuns"""
        self.log("Verificando diretórios comuns...", "INFO")
        
        common_dirs = [
            '/admin',
            '/administrator',
            '/backup',
            '/config',
            '/database',
            '/db',
            '/dev',
            '/files',
            '/images',
            '/img',
            '/includes',
            '/js',
            '/lib',
            '/library',
            '/logs',
            '/media',
            '/modules',
            '/plugins',
            '/scripts',
            '/src',
            '/static',
            '/temp',
            '/test',
            '/tmp',
            '/uploads',
            '/vendor'
        ]
        
        def check_directory(dir_path):
            try:
                test_url = urljoin(self.target_url, dir_path)
                response = self.session.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    self.log(f"Diretório encontrado: {dir_path}", "SUCCESS")
                    # Verificar se é listagem de diretório
                    if 'Index of' in response.text or 'Directory listing' in response.text:
                        self.add_vulnerability(
                            "Directory Listing",
                            f"Listagem de diretório habilitada: {dir_path}",
                            "MEDIUM",
                            f"URL: {test_url}"
                        )
                        
            except Exception as e:
                if self.verbose:
                    self.log(f"Erro ao verificar {dir_path}: {e}", "WARNING")
        
        # Usar ThreadPoolExecutor para verificar diretórios em paralelo
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_directory, common_dirs)
    
    def setup_audit_log(self):
        Path("logs").mkdir(exist_ok=True, mode=0o700)
        logging.basicConfig(filename=self.audit_log_path, level=logging.INFO, format='%(asctime)s %(message)s')
        os.chmod(self.audit_log_path, 0o600)
    
    def log_audit_event(self):
        user = getpass.getuser()
        logging.info(f"[AUDIT] Usuário: {user} | Alvo: {self.target_url} | Data/Hora: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    def ensure_reports_dir(self):
        Path("reports").mkdir(exist_ok=True, mode=0o700)
    
    def generate_report(self):
        """Gera relatório final (com proteção de permissão)"""
        self.log("Gerando relatório...", "INFO")
        report = {
            'target': self.target_url,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': self.vulnerabilities,
            'open_ports': self.ports,
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical': len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']),
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']),
                'low': len([v for v in self.vulnerabilities if v['severity'] == 'LOW'])
            }
        }
        report_path = f'reports/scan_report_{int(time.time())}.json'
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        os.chmod(report_path, 0o600)
        
        # Exibir resumo
        print(f"\n{Fore.CYAN}══════════════════════════════════════════════════════════════")
        print(f"                    RELATÓRIO FINAL")
        print(f"══════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Target: {self.target_url}")
        print(f"Data do Scan: {report['scan_date']}")
        print(f"Portas Abertas: {', '.join(map(str, self.ports)) if self.ports else 'Nenhuma'}")
        
        print(f"\n{Fore.RED}Vulnerabilidades Encontradas: {report['summary']['total_vulnerabilities']}")
        print(f"  • Críticas: {report['summary']['critical']}")
        print(f"  • Altas: {report['summary']['high']}")
        print(f"  • Médias: {report['summary']['medium']}")
        print(f"  • Baixas: {report['summary']['low']}{Style.RESET_ALL}")
        
        if self.vulnerabilities:
            print(f"\n{Fore.RED}Detalhes das Vulnerabilidades:{Style.RESET_ALL}")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                color = {
                    'CRITICAL': Fore.RED + Style.BRIGHT,
                    'HIGH': Fore.RED,
                    'MEDIUM': Fore.YELLOW,
                    'LOW': Fore.BLUE
                }.get(vuln['severity'], Fore.WHITE)
                
                print(f"\n{color}[{i}] {vuln['type']} ({vuln['severity']}){Style.RESET_ALL}")
                print(f"    Descrição: {vuln['description']}")
                if vuln['evidence']:
                    print(f"    Evidência: {vuln['evidence']}")
        
        print(f"\n{Fore.GREEN}Relatório salvo em: {report_path}{Style.RESET_ALL}")
    
    def run_full_scan(self):
        """Executa scan completo"""
        self.print_banner()
        
        # Executar todos os scans
        scans = [
            self.scan_dns,
            self.scan_ports,
            self.check_ssl_certificate,
            self.scan_headers,
            self.scan_robots_txt,
            self.scan_sitemap,
            self.scan_common_files,
            self.scan_common_directories,
            self.scan_directory_traversal,
            self.scan_sql_injection,
            self.scan_xss,
            self.scan_open_redirect
        ]
        
        for scan in scans:
            try:
                scan()
                time.sleep(1)  # Pequena pausa entre scans
            except Exception as e:
                self.log(f"Erro durante scan: {e}", "ERROR")
        
        self.generate_report()

def main():
    if os.geteuid() == 0:
        print(f"{Fore.RED}Por segurança, não execute como root!{Style.RESET_ALL}")
        sys.exit(1)
    print(f"{Fore.RED}AVISO LEGAL: Use esta ferramenta apenas em sistemas que você possui ou tem autorização explícita. O uso indevido é crime!{Style.RESET_ALL}")
    # Não exige mais senha
    parser = argparse.ArgumentParser(
        description='Web Vulnerability Scanner - Red Team Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python web_scanner.py https://example.com
  python web_scanner.py https://example.com --verbose
  python web_scanner.py https://example.com --threads 20
        """
    )
    
    parser.add_argument('url', help='URL alvo para scan')
    parser.add_argument('--verbose', '-v', action='store_true', help='Modo verboso')
    parser.add_argument('--threads', '-t', type=int, default=10, help='Número de threads (padrão: 10)')
    
    args = parser.parse_args()
    
    if not is_valid_url(args.url):
        print(f"{Fore.RED}URL inválida ou esquema não suportado! Use apenas http(s).{Style.RESET_ALL}")
        sys.exit(1)
    domain = urlparse(args.url).netloc
    if is_private_ip(domain):
        print(f"{Fore.RED}Por segurança, não é permitido scan em IPs privados/locais!{Style.RESET_ALL}")
        sys.exit(1)
    if not is_domain_allowed(domain):
        print(f"{Fore.RED}Domínio não autorizado. Adicione o domínio em allowed_domains.txt para permitir o scan.{Style.RESET_ALL}")
        sys.exit(1)
    
    try:
        scanner = WebVulnerabilityScanner(args.url, args.verbose, args.threads)
        scanner.run_full_scan()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrompido pelo usuário{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}Erro fatal: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main() 