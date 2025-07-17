#!/usr/bin/env python3
"""
Red Team Automation Script
Script de automação para testes de penetração web
"""

import subprocess
import sys
import os
import time
import json
import argparse
from colorama import init, Fore, Style
import requests
from urllib.parse import urlparse
import shlex
import getpass
import logging
from pathlib import Path
import ipaddress
import socket
import hashlib

# Inicializar colorama
init(autoreset=True)

def is_valid_url(url):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.netloc:
        return False
    return True

def log_audit_event(url):
    Path("logs").mkdir(exist_ok=True, mode=0o700)
    logging.basicConfig(filename="logs/audit.log", level=logging.INFO, format='%(asctime)s %(message)s')
    import time
    user = getpass.getuser()
    logging.info(f"[AUDIT] Usuário: {user} | Alvo: {url} | Data/Hora: {time.strftime('%Y-%m-%d %H:%M:%S')}")

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

class RedTeamAutomation:
    def __init__(self, target_url, output_dir="reports"):
        if not is_valid_url(target_url):
            print(f"URL inválida ou esquema não suportado! Use apenas http(s).")
            sys.exit(1)
        self.target_url = target_url
        self.output_dir = output_dir
        self.domain = urlparse(target_url).netloc
        self.results = {}
        
        # Criar diretório de saída com permissão restrita
        Path(output_dir).mkdir(exist_ok=True, mode=0o700)
    
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
    
    def print_banner(self):
        """Exibe banner do red team"""
        banner = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║                    RED TEAM AUTOMATION                          ║
║                    WEB PENETRATION TESTING                      ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}Target: {self.target_url}
{Fore.CYAN}Domain: {self.domain}
{Fore.GREEN}Output Directory: {self.output_dir}
{Style.RESET_ALL}
"""
        print(banner)
    
    def run_nmap_scan(self):
        """Executa scan com Nmap (sanitizado)"""
        self.log("Iniciando scan Nmap...", "INFO")
        
        try:
            # Segurança: sanitizar domínio e diretório de saída
            safe_domain = shlex.quote(self.domain)
            safe_output = shlex.quote(f"{self.output_dir}/nmap_scan.txt")
            cmd = ["nmap", "-sS", "-sV", "-O", "-p-", safe_domain, "-oN", safe_output]
            self.log(f"Executando: {' '.join(cmd)}", "INFO")
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log("Scan Nmap concluído com sucesso", "SUCCESS")
                self.results['nmap'] = {
                    'status': 'success',
                    'output_file': f"{self.output_dir}/nmap_scan.txt"
                }
            else:
                self.log(f"Erro no scan Nmap: {result.stderr}", "ERROR")
                self.results['nmap'] = {
                    'status': 'error',
                    'error': result.stderr
                }
                
        except Exception as e:
            self.log(f"Erro ao executar Nmap: {e}", "ERROR")
            self.results['nmap'] = {
                'status': 'error',
                'error': str(e)
            }
    
    def run_dirb_scan(self):
        """Executa scan de diretórios com Dirb (sanitizado)"""
        self.log("Iniciando scan Dirb...", "INFO")
        
        try:
            safe_url = shlex.quote(self.target_url)
            safe_output = shlex.quote(f"{self.output_dir}/dirb_scan.txt")
            cmd = ["dirb", safe_url, "/usr/share/dirb/wordlists/common.txt", "-o", safe_output]
            self.log(f"Executando: {' '.join(cmd)}", "INFO")
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log("Scan Dirb concluído com sucesso", "SUCCESS")
                self.results['dirb'] = {
                    'status': 'success',
                    'output_file': f"{self.output_dir}/dirb_scan.txt"
                }
            else:
                self.log(f"Erro no scan Dirb: {result.stderr}", "ERROR")
                self.results['dirb'] = {
                    'status': 'error',
                    'error': result.stderr
                }
                
        except Exception as e:
            self.log(f"Erro ao executar Dirb: {e}", "ERROR")
            self.results['dirb'] = {
                'status': 'error',
                'error': str(e)
            }
    
    def run_nikto_scan(self):
        """Executa scan com Nikto (sanitizado)"""
        self.log("Iniciando scan Nikto...", "INFO")
        
        try:
            safe_url = shlex.quote(self.target_url)
            safe_output = shlex.quote(f"{self.output_dir}/nikto_scan.txt")
            cmd = ["nikto", "-h", safe_url, "-o", safe_output]
            self.log(f"Executando: {' '.join(cmd)}", "INFO")
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log("Scan Nikto concluído com sucesso", "SUCCESS")
                self.results['nikto'] = {
                    'status': 'success',
                    'output_file': f"{self.output_dir}/nikto_scan.txt"
                }
            else:
                self.log(f"Erro no scan Nikto: {result.stderr}", "ERROR")
                self.results['nikto'] = {
                    'status': 'error',
                    'error': result.stderr
                }
                
        except Exception as e:
            self.log(f"Erro ao executar Nikto: {e}", "ERROR")
            self.results['nikto'] = {
                'status': 'error',
                'error': str(e)
            }
    
    def run_sqlmap_scan(self):
        """Executa scan com SQLMap (sanitizado)"""
        self.log("Iniciando scan SQLMap...", "INFO")
        
        try:
            safe_url = shlex.quote(self.target_url)
            safe_output = shlex.quote(f"{self.output_dir}/sqlmap")
            cmd = ["sqlmap", "-u", safe_url, "--batch", "--random-agent", "--level=1", "--risk=1", f"--output-dir={safe_output}"]
            self.log(f"Executando: {' '.join(cmd)}", "INFO")
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log("Scan SQLMap concluído com sucesso", "SUCCESS")
                self.results['sqlmap'] = {
                    'status': 'success',
                    'output_dir': f"{self.output_dir}/sqlmap"
                }
            else:
                self.log(f"Erro no scan SQLMap: {result.stderr}", "ERROR")
                self.results['sqlmap'] = {
                    'status': 'error',
                    'error': result.stderr
                }
                
        except Exception as e:
            self.log(f"Erro ao executar SQLMap: {e}", "ERROR")
            self.results['sqlmap'] = {
                'status': 'error',
                'error': str(e)
            }
    
    def run_nuclei_scan(self):
        """Executa scan com Nuclei (sanitizado)"""
        self.log("Iniciando scan Nuclei...", "INFO")
        
        try:
            safe_url = shlex.quote(self.target_url)
            safe_output = shlex.quote(f"{self.output_dir}/nuclei_scan.txt")
            cmd = ["nuclei", "-u", safe_url, "-o", safe_output]
            self.log(f"Executando: {' '.join(cmd)}", "INFO")
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log("Scan Nuclei concluído com sucesso", "SUCCESS")
                self.results['nuclei'] = {
                    'status': 'success',
                    'output_file': f"{self.output_dir}/nuclei_scan.txt"
                }
            else:
                self.log(f"Erro no scan Nuclei: {result.stderr}", "ERROR")
                self.results['nuclei'] = {
                    'status': 'error',
                    'error': result.stderr
                }
                
        except Exception as e:
            self.log(f"Erro ao executar Nuclei: {e}", "ERROR")
            self.results['nuclei'] = {
                'status': 'error',
                'error': str(e)
            }
    
    def run_custom_scanner(self):
        """Executa scanner customizado (sanitizado)"""
        self.log("Iniciando scanner customizado...", "INFO")
        
        try:
            safe_url = shlex.quote(self.target_url)
            cmd = ["python3", "web_scanner.py", safe_url, "--verbose"]
            self.log(f"Executando: {' '.join(cmd)}", "INFO")
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log("Scanner customizado concluído com sucesso", "SUCCESS")
                self.results['custom_scanner'] = {
                    'status': 'success',
                    'output': result.stdout
                }
            else:
                self.log(f"Erro no scanner customizado: {result.stderr}", "ERROR")
                self.results['custom_scanner'] = {
                    'status': 'error',
                    'error': result.stderr
                }
                
        except Exception as e:
            self.log(f"Erro ao executar scanner customizado: {e}", "ERROR")
            self.results['custom_scanner'] = {
                'status': 'error',
                'error': str(e)
            }
    
    def run_advanced_scanner(self):
        """Executa scanner avançado (sanitizado)"""
        self.log("Iniciando scanner avançado...", "INFO")
        
        try:
            safe_url = shlex.quote(self.target_url)
            cmd = ["python3", "advanced_scanner.py", safe_url]
            self.log(f"Executando: {' '.join(cmd)}", "INFO")
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log("Scanner avançado concluído com sucesso", "SUCCESS")
                self.results['advanced_scanner'] = {
                    'status': 'success',
                    'output': result.stdout
                }
            else:
                self.log(f"Erro no scanner avançado: {result.stderr}", "ERROR")
                self.results['advanced_scanner'] = {
                    'status': 'error',
                    'error': result.stderr
                }
                
        except Exception as e:
            self.log(f"Erro ao executar scanner avançado: {e}", "ERROR")
            self.results['advanced_scanner'] = {
                'status': 'error',
                'error': str(e)
            }
    
    def generate_summary_report(self):
        """Gera relatório resumido"""
        self.log("Gerando relatório resumido...", "INFO")
        
        summary = {
            'target': self.target_url,
            'domain': self.domain,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'tools_executed': list(self.results.keys()),
            'results': self.results,
            'summary': {
                'total_tools': len(self.results),
                'successful_scans': len([r for r in self.results.values() if r['status'] == 'success']),
                'failed_scans': len([r for r in self.results.values() if r['status'] == 'error'])
            }
        }
        
        # Salvar relatório
        report_file = f"{self.output_dir}/red_team_summary.json"
        with open(report_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Exibir resumo
        print(f"\n{Fore.CYAN}══════════════════════════════════════════════════════════════")
        print(f"                    RELATÓRIO RESUMIDO")
        print(f"══════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Target: {self.target_url}")
        print(f"Data: {summary['scan_date']}")
        print(f"Ferramentas executadas: {summary['summary']['total_tools']}")
        print(f"Scans bem-sucedidos: {summary['summary']['successful_scans']}")
        print(f"Scans com erro: {summary['summary']['failed_scans']}")
        
        print(f"\n{Fore.GREEN}Ferramentas executadas:{Style.RESET_ALL}")
        for tool, result in self.results.items():
            status_color = Fore.GREEN if result['status'] == 'success' else Fore.RED
            print(f"  • {tool}: {status_color}{result['status'].upper()}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}Relatório salvo em: {report_file}{Style.RESET_ALL}")
    
    def run_full_automation(self):
        """Executa automação completa"""
        self.print_banner()
        
        tools = [
            self.run_nmap_scan,
            self.run_dirb_scan,
            self.run_nikto_scan,
            self.run_sqlmap_scan,
            self.run_nuclei_scan,
            self.run_custom_scanner,
            self.run_advanced_scanner
        ]
        
        for tool in tools:
            try:
                tool()
                time.sleep(2)  # Pausa entre ferramentas
            except Exception as e:
                self.log(f"Erro durante execução: {e}", "ERROR")
        
        self.generate_summary_report()

def check_tools():
    """Verifica se as ferramentas estão instaladas"""
    tools = ['nmap', 'dirb', 'nikto', 'sqlmap', 'nuclei']
    missing_tools = []
    
    for tool in tools:
        try:
            subprocess.run([tool, '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"{Fore.YELLOW}Aviso: As seguintes ferramentas não foram encontradas:")
        for tool in missing_tools:
            print(f"  • {tool}")
        print(f"{Style.RESET_ALL}")
        return False
    
    return True

def main():
    if os.geteuid() == 0:
        print(f"{Fore.RED}Por segurança, não execute como root!{Style.RESET_ALL}")
        sys.exit(1)
    print(f"{Fore.RED}AVISO LEGAL: Use esta ferramenta apenas em sistemas que você possui ou tem autorização explícita. O uso indevido é crime!{Style.RESET_ALL}")
    # Não exige mais senha
    parser = argparse.ArgumentParser(
        description='Red Team Automation - Web Penetration Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python red_team_automation.py https://example.com
  python red_team_automation.py https://example.com --output-dir ./my_reports
        """
    )
    
    parser.add_argument('url', help='URL alvo para teste de penetração')
    parser.add_argument('--output-dir', '-o', default='reports', help='Diretório de saída (padrão: reports)')
    parser.add_argument('--check-tools', action='store_true', help='Verificar se as ferramentas estão instaladas')
    
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

    if args.check_tools:
        if check_tools():
            print(f"{Fore.GREEN}Todas as ferramentas estão instaladas!{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Algumas ferramentas estão faltando. Instale-as antes de continuar.{Style.RESET_ALL}")
        return
    
    try:
        automation = RedTeamAutomation(args.url, args.output_dir)
        automation.run_full_automation()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Automação interrompida pelo usuário{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}Erro fatal: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main() 