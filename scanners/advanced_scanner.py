#!/usr/bin/env python3
"""
Advanced Web Vulnerability Scanner - Red Team Module
Módulo avançado para testes de penetração web
"""

import requests
import subprocess
import json
import time
import re
import os
import sys
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style
import threading
from concurrent.futures import ThreadPoolExecutor
import nmap
import socket
import ssl
from bs4 import BeautifulSoup
import getpass
import logging
import stat
from pathlib import Path
import ipaddress

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

class AdvancedScanner:
    def __init__(self, target_url, verbose=False):
        if not is_valid_url(target_url):
            print(f"URL inválida ou esquema não suportado! Use apenas http(s).")
            sys.exit(1)
        self.target_url = target_url
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.findings = []
        self.audit_log_path = "logs/audit.log"
        self.setup_audit_log()
        self.log_audit_event()
        self.ensure_reports_dir()
        
    def log(self, message, level="INFO"):
        """Sistema de logging"""
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
    
    def add_finding(self, finding_type, description, severity, evidence=None):
        """Adiciona um achado de segurança"""
        finding = {
            'type': finding_type,
            'description': description,
            'severity': severity,
            'evidence': evidence,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
        }
        self.findings.append(finding)
        self.log(f"Achado: {finding_type} - {severity}", "CRITICAL")
    
    def scan_subdomains(self):
        """Escaneia subdomínios"""
        self.log("Iniciando scan de subdomínios...", "INFO")
        
        domain = urlparse(self.target_url).netloc
        base_domain = '.'.join(domain.split('.')[-2:])
        
        # Lista de subdomínios comuns
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'staging',
            'api', 'cdn', 'static', 'img', 'images', 'media', 'files',
            'support', 'help', 'docs', 'wiki', 'forum', 'shop', 'store',
            'app', 'mobile', 'm', 'secure', 'login', 'auth', 'dashboard',
            'panel', 'cpanel', 'webmail', 'ns1', 'ns2', 'dns', 'mx'
        ]
        
        found_subdomains = []
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{base_domain}"
                ip = socket.gethostbyname(full_domain)
                found_subdomains.append((full_domain, ip))
                self.log(f"Subdomínio encontrado: {full_domain} -> {ip}", "SUCCESS")
            except socket.gaierror:
                pass
            except Exception as e:
                if self.verbose:
                    self.log(f"Erro ao verificar {subdomain}: {e}", "WARNING")
        
        # Verificar subdomínios em paralelo
        with ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_subdomain, common_subdomains)
        
        if found_subdomains:
            self.add_finding(
                "Subdomains Discovery",
                f"Encontrados {len(found_subdomains)} subdomínios",
                "MEDIUM",
                f"Subdomínios: {[s[0] for s in found_subdomains]}"
            )
        
        return found_subdomains
    
    def scan_technologies(self):
        """Detecta tecnologias utilizadas"""
        self.log("Detectando tecnologias...", "INFO")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            content = response.text
            
            technologies = []
            
            # Verificar por tecnologias comuns
            tech_signatures = {
                'WordPress': ['wp-content', 'wp-includes', 'wp-admin'],
                'Drupal': ['drupal', 'sites/default'],
                'Joomla': ['joomla', 'components/com_'],
                'Magento': ['magento', 'skin/frontend'],
                'Laravel': ['laravel', 'csrf-token'],
                'Django': ['csrfmiddlewaretoken', 'django'],
                'ASP.NET': ['asp.net', 'viewstate'],
                'PHP': ['php', 'phpinfo'],
                'Apache': ['apache', 'mod_'],
                'Nginx': ['nginx'],
                'IIS': ['iis', 'microsoft'],
                'Cloudflare': ['cloudflare'],
                'AWS': ['aws', 'amazon'],
                'Google Analytics': ['google-analytics', 'gtag'],
                'Facebook Pixel': ['facebook', 'fbq'],
                'jQuery': ['jquery'],
                'Bootstrap': ['bootstrap'],
                'React': ['react', 'reactjs'],
                'Angular': ['angular', 'ng-'],
                'Vue.js': ['vue', 'v-']
            }
            
            for tech, signatures in tech_signatures.items():
                for signature in signatures:
                    if signature.lower() in content.lower() or signature.lower() in str(headers).lower():
                        technologies.append(tech)
                        break
            
            # Verificar headers específicos
            server_header = headers.get('Server', '')
            if server_header:
                technologies.append(f"Server: {server_header}")
            
            x_powered_by = headers.get('X-Powered-By', '')
            if x_powered_by:
                technologies.append(f"Powered by: {x_powered_by}")
            
            if technologies:
                self.log(f"Tecnologias detectadas: {', '.join(set(technologies))}", "SUCCESS")
                self.add_finding(
                    "Technology Disclosure",
                    f"Tecnologias detectadas: {', '.join(set(technologies))}",
                    "LOW",
                    f"Tecnologias: {technologies}"
                )
            
            return list(set(technologies))
            
        except Exception as e:
            self.log(f"Erro ao detectar tecnologias: {e}", "ERROR")
            return []
    
    def scan_ssl_vulnerabilities(self):
        """Verifica vulnerabilidades SSL/TLS"""
        self.log("Verificando vulnerabilidades SSL/TLS...", "INFO")
        
        try:
            domain = urlparse(self.target_url).netloc
            
            # Verificar versões SSL/TLS suportadas
            ssl_versions = {
                'SSLv2': ssl.PROTOCOL_SSLv2,
                'SSLv3': ssl.PROTOCOL_SSLv3,
                'TLSv1.0': ssl.PROTOCOL_TLSv1,
                'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
                'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
                'TLSv1.3': ssl.PROTOCOL_TLSv1_3
            }
            
            vulnerable_versions = []
            
            for version_name, version_protocol in ssl_versions.items():
                try:
                    context = ssl.SSLContext(version_protocol)
                    with socket.create_connection((domain, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            if version_name in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                                vulnerable_versions.append(version_name)
                                self.log(f"Versão vulnerável suportada: {version_name}", "WARNING")
                except Exception:
                    pass
            
            if vulnerable_versions:
                self.add_finding(
                    "Weak SSL/TLS Configuration",
                    f"Versões SSL/TLS vulneráveis suportadas: {', '.join(vulnerable_versions)}",
                    "HIGH",
                    f"Versões vulneráveis: {vulnerable_versions}"
                )
            
            # Verificar cipher suites fracos
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cipher = ssock.cipher()
                        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5']
                        
                        for weak_cipher in weak_ciphers:
                            if weak_cipher in cipher[0]:
                                self.add_finding(
                                    "Weak Cipher Suite",
                                    f"Cipher suite fraco detectado: {cipher[0]}",
                                    "MEDIUM",
                                    f"Cipher: {cipher[0]}"
                                )
                                break
            except Exception as e:
                self.log(f"Erro ao verificar cipher suites: {e}", "ERROR")
                
        except Exception as e:
            self.log(f"Erro ao verificar SSL: {e}", "ERROR")
    
    def scan_http_methods(self):
        """Testa métodos HTTP permitidos"""
        self.log("Testando métodos HTTP...", "INFO")
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'PATCH']
        allowed_methods = []
        
        for method in methods:
            try:
                response = self.session.request(method, self.target_url, timeout=5)
                if response.status_code not in [405, 501, 403]:
                    allowed_methods.append(method)
                    self.log(f"Método {method} permitido (Status: {response.status_code})", "SUCCESS")
            except Exception as e:
                if self.verbose:
                    self.log(f"Erro ao testar método {method}: {e}", "WARNING")
        
        # Verificar métodos perigosos
        dangerous_methods = ['PUT', 'DELETE', 'TRACE']
        found_dangerous = [m for m in allowed_methods if m in dangerous_methods]
        
        if found_dangerous:
            self.add_finding(
                "Dangerous HTTP Methods",
                f"Métodos HTTP perigosos permitidos: {', '.join(found_dangerous)}",
                "MEDIUM",
                f"Métodos perigosos: {found_dangerous}"
            )
        
        return allowed_methods
    
    def scan_information_disclosure(self):
        """Verifica vazamento de informações"""
        self.log("Verificando vazamento de informações...", "INFO")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            content = response.text
            
            # Verificar por informações sensíveis
            sensitive_patterns = [
                r'error in your SQL syntax',
                r'mysql_fetch_array',
                r'oracle error',
                r'postgresql error',
                r'sql server error',
                r'microsoft ole db provider',
                r'stack trace',
                r'debug information',
                r'php warning',
                r'php fatal error',
                r'apache error',
                r'nginx error',
                r'file not found',
                r'permission denied',
                r'access denied',
                r'username:',
                r'password:',
                r'database:',
                r'host:',
                r'port:',
                r'api_key',
                r'secret_key',
                r'private_key',
                r'access_token',
                r'bearer token'
            ]
            
            for pattern in sensitive_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    self.add_finding(
                        "Information Disclosure",
                        f"Informações sensíveis expostas: {pattern}",
                        "HIGH",
                        f"Padrão: {pattern}, Matches: {len(matches)}"
                    )
            
            # Verificar comentários HTML
            soup = BeautifulSoup(content, 'html.parser')
            comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))
            
            for comment in comments:
                comment_text = comment.strip()
                if any(sensitive in comment_text.lower() for sensitive in ['password', 'secret', 'key', 'token', 'admin']):
                    self.add_finding(
                        "Sensitive Information in Comments",
                        "Informações sensíveis em comentários HTML",
                        "MEDIUM",
                        f"Comentário: {comment_text[:100]}..."
                    )
                    
        except Exception as e:
            self.log(f"Erro ao verificar vazamento de informações: {e}", "ERROR")
    
    def scan_cors_misconfiguration(self):
        """Verifica configurações incorretas de CORS"""
        self.log("Verificando configurações CORS...", "INFO")
        
        try:
            # Testar com diferentes origins
            test_origins = [
                'https://evil.com',
                'http://evil.com',
                'null',
                'https://attacker.com',
                'https://malicious-site.com'
            ]
            
            for origin in test_origins:
                headers = {'Origin': origin}
                response = self.session.get(self.target_url, headers=headers, timeout=5)
                
                acao = response.headers.get('Access-Control-Allow-Origin')
                if acao:
                    if acao == '*' or origin in acao:
                        self.add_finding(
                            "CORS Misconfiguration",
                            f"Configuração CORS permissiva: {acao}",
                            "MEDIUM",
                            f"Origin: {origin}, ACAO: {acao}"
                        )
                        break
                        
        except Exception as e:
            self.log(f"Erro ao verificar CORS: {e}", "ERROR")
    
    def scan_clickjacking(self):
        """Testa vulnerabilidade de clickjacking"""
        self.log("Testando clickjacking...", "INFO")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            x_frame_options = headers.get('X-Frame-Options', '')
            content_security_policy = headers.get('Content-Security-Policy', '')
            
            if not x_frame_options and 'frame-ancestors' not in content_security_policy.lower():
                self.add_finding(
                    "Clickjacking Vulnerability",
                    "Proteção contra clickjacking ausente",
                    "MEDIUM",
                    "X-Frame-Options ou CSP frame-ancestors não configurados"
                )
            elif x_frame_options.lower() == 'sameorigin':
                self.log("X-Frame-Options configurado como SAMEORIGIN", "SUCCESS")
            elif x_frame_options.lower() == 'deny':
                self.log("X-Frame-Options configurado como DENY", "SUCCESS")
                
        except Exception as e:
            self.log(f"Erro ao verificar clickjacking: {e}", "ERROR")
    
    def scan_ssrf_potential(self):
        """Verifica potencial para SSRF"""
        self.log("Verificando potencial para SSRF...", "INFO")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            content = response.text
            
            # Procurar por parâmetros que podem ser usados para SSRF
            ssrf_params = ['url', 'uri', 'path', 'src', 'dest', 'redirect', 'redirect_uri', 
                          'callback', 'return_url', 'next', 'target', 'redir', 'destination',
                          'link', 'image', 'file', 'page', 'folder', 'dir', 'directory']
            
            # Extrair URLs da página
            url_pattern = r'https?://[^\s<>"\']+'
            urls = re.findall(url_pattern, content)
            
            # Verificar se há parâmetros que aceitam URLs
            for param in ssrf_params:
                if param in content.lower():
                    self.add_finding(
                        "Potential SSRF Parameter",
                        f"Parâmetro potencial para SSRF: {param}",
                        "MEDIUM",
                        f"Parâmetro: {param}"
                    )
            
            # Verificar URLs internas
            internal_urls = []
            for url in urls:
                parsed = urlparse(url)
                if parsed.netloc and parsed.netloc != urlparse(self.target_url).netloc:
                    internal_urls.append(url)
            
            if internal_urls:
                self.add_finding(
                    "Internal URLs Exposure",
                    f"URLs internas expostas: {len(internal_urls)}",
                    "MEDIUM",
                    f"URLs internas: {internal_urls[:5]}"  # Mostrar apenas as primeiras 5
                )
                
        except Exception as e:
            self.log(f"Erro ao verificar SSRF: {e}", "ERROR")
    
    def setup_audit_log(self):
        Path("logs").mkdir(exist_ok=True, mode=0o700)
        logging.basicConfig(filename=self.audit_log_path, level=logging.INFO, format='%(asctime)s %(message)s')
        os.chmod(self.audit_log_path, 0o600)
    def log_audit_event(self):
        user = getpass.getuser()
        logging.info(f"[AUDIT] Usuário: {user} | Alvo: {self.target_url} | Data/Hora: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    def ensure_reports_dir(self):
        Path("reports").mkdir(exist_ok=True, mode=0o700)
    def run_advanced_scan(self):
        self.log("Iniciando scan avançado...", "INFO")
        
        scans = [
            self.scan_subdomains,
            self.scan_technologies,
            self.scan_ssl_vulnerabilities,
            self.scan_http_methods,
            self.scan_information_disclosure,
            self.scan_cors_misconfiguration,
            self.scan_clickjacking,
            self.scan_ssrf_potential
        ]
        
        for scan in scans:
            try:
                scan()
                time.sleep(1)
            except Exception as e:
                self.log(f"Erro durante scan avançado: {e}", "ERROR")
        self.generate_report()
    def generate_report(self):
        report = {
            'target': self.target_url,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'findings': self.findings
        }
        report_path = f'reports/advanced_scan_report_{int(time.time())}.json'
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        os.chmod(report_path, 0o600)
        print(f"\nRelatório salvo em: {report_path}")

def main():
    if os.geteuid() == 0:
        print("Por segurança, não execute como root!")
        sys.exit(1)
    print("AVISO LEGAL: Use esta ferramenta apenas em sistemas que você possui ou tem autorização explícita. O uso indevido é crime!")
    # Não exige mais senha
    if len(sys.argv) != 2:
        print("Uso: python advanced_scanner.py <url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    if not is_valid_url(target_url):
        print("URL inválida ou esquema não suportado! Use apenas http(s).")
        sys.exit(1)
    
    domain = urlparse(target_url).netloc
    if is_private_ip(domain):
        print("Por segurança, não é permitido scan em IPs privados/locais!")
        sys.exit(1)
    if not is_domain_allowed(domain):
        print("Domínio não autorizado. Adicione o domínio em allowed_domains.txt para permitir o scan.")
        sys.exit(1)

    scanner = AdvancedScanner(target_url, verbose=True)
    findings = scanner.run_advanced_scan()
    
    print(f"\n{Fore.CYAN}══════════════════════════════════════════════════════════════")
    print(f"                    SCAN AVANÇADO CONCLUÍDO")
    print(f"══════════════════════════════════════════════════════════════{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}Total de achados: {len(findings)}")
    
    if findings:
        for i, finding in enumerate(findings, 1):
            color = {
                'CRITICAL': Fore.RED + Style.BRIGHT,
                'HIGH': Fore.RED,
                'MEDIUM': Fore.YELLOW,
                'LOW': Fore.BLUE
            }.get(finding['severity'], Fore.WHITE)
            
            print(f"\n{color}[{i}] {finding['type']} ({finding['severity']}){Style.RESET_ALL}")
            print(f"    Descrição: {finding['description']}")
            if finding['evidence']:
                print(f"    Evidência: {finding['evidence']}")

if __name__ == "__main__":
    main() 