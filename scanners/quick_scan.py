#!/usr/bin/env python3
"""
Quick Scan - Execução Rápida
Script para execução rápida de scans básicos
"""

import sys
import argparse
from colorama import init, Fore, Style
import getpass
import logging
from pathlib import Path
import ipaddress
import socket
import os
from urllib.parse import urlparse

# Inicializar colorama
init(autoreset=True)

def print_banner():
    """Exibe banner do quick scan"""
    banner = f"""
{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗
║                    QUICK SCAN - EXECUÇÃO RÁPIDA                   ║
║                    WEB VULNERABILITY SCANNER                      ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

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

def log_audit_event(url):
    Path("logs").mkdir(exist_ok=True, mode=0o700)
    logging.basicConfig(filename="logs/audit.log", level=logging.INFO, format='%(asctime)s %(message)s')
    import time
    user = getpass.getuser()
    logging.info(f"[AUDIT] Usuário: {user} | Alvo: {url} | Data/Hora: {time.strftime('%Y-%m-%d %H:%M:%S')}")

def quick_scan(url, scan_type="basic"):
    """Executa scan rápido"""
    try:
        if scan_type == "basic":
            print(f"{Fore.CYAN}Executando scan básico em: {url}{Style.RESET_ALL}")
            
            # Importar scanner básico
            sys.path.append('.')
            from web_scanner import WebVulnerabilityScanner
            
            scanner = WebVulnerabilityScanner(url, verbose=True, threads=5)
            
            # Executar apenas scans essenciais
            scanner.scan_dns()
            scanner.scan_headers()
            scanner.scan_robots_txt()
            scanner.scan_common_files()
            
            print(f"{Fore.GREEN}✓ Scan básico concluído{Style.RESET_ALL}")
            
        elif scan_type == "advanced":
            print(f"{Fore.CYAN}Executando scan avançado em: {url}{Style.RESET_ALL}")
            
            # Importar scanner avançado
            sys.path.append('.')
            from advanced_scanner import AdvancedScanner
            
            scanner = AdvancedScanner(url, verbose=True)
            findings = scanner.run_advanced_scan()
            
            print(f"{Fore.GREEN}✓ Scan avançado concluído - {len(findings)} achados{Style.RESET_ALL}")
            
        elif scan_type == "full":
            print(f"{Fore.CYAN}Executando scan completo em: {url}{Style.RESET_ALL}")
            
            # Importar automação completa
            sys.path.append('.')
            from red_team_automation import RedTeamAutomation
            
            automation = RedTeamAutomation(url, "quick_reports")
            automation.run_full_automation()
            
            print(f"{Fore.GREEN}✓ Scan completo concluído{Style.RESET_ALL}")
            
    except ImportError as e:
        print(f"{Fore.RED}Erro: {e}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Execute primeiro: pip3 install -r requirements.txt{Style.RESET_ALL}")
        return False
    except Exception as e:
        print(f"{Fore.RED}Erro durante o scan: {e}{Style.RESET_ALL}")
        return False
    
    return True

def main():
    if os.geteuid() == 0:
        print(f"{Fore.RED}Por segurança, não execute como root!{Style.RESET_ALL}")
        sys.exit(1)
    print(f"{Fore.RED}AVISO LEGAL: Use esta ferramenta apenas em sistemas que você possui ou tem autorização explícita. O uso indevido é crime!{Style.RESET_ALL}")
    # Não exige mais senha
    parser = argparse.ArgumentParser(
        description='Quick Scan - Execução Rápida de Web Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Tipos de scan disponíveis:
  basic     - Scan básico (DNS, Headers, Robots.txt, Arquivos comuns)
  advanced  - Scan avançado (Subdomínios, Tecnologias, SSL, CORS, etc.)
  full      - Automação completa (todas as ferramentas)

Exemplos de uso:
  python3 quick_scan.py https://example.com
  python3 quick_scan.py https://example.com --type advanced
  python3 quick_scan.py https://example.com --type full
        """
    )
    
    parser.add_argument('url', help='URL alvo para scan')
    parser.add_argument('--type', '-t', choices=['basic', 'advanced', 'full'], 
                       default='basic', help='Tipo de scan (padrão: basic)')
    
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
    log_audit_event(args.url)
    
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    print_banner()
    
    print(f"{Fore.YELLOW}URL: {args.url}")
    print(f"{Fore.YELLOW}Tipo: {args.type}")
    print(f"{Fore.CYAN}Iniciando scan...{Style.RESET_ALL}")
    
    try:
        success = quick_scan(args.url, args.type)
        if success:
            print(f"\n{Fore.GREEN}Scan concluído com sucesso!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Verifique os relatórios gerados.{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}Scan falhou. Verifique os erros acima.{Style.RESET_ALL}")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrompido pelo usuário{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}Erro fatal: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main() 