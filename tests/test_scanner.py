#!/usr/bin/env python3
"""
Test Script for Web Vulnerability Scanner
Script de teste para demonstrar o funcionamento do scanner
"""

import sys
import os
import time
from colorama import init, Fore, Style
import getpass
import logging
from pathlib import Path

# Inicializar colorama
init(autoreset=True)

def print_banner():
    """Exibe banner de teste"""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    TESTE DO SCANNER                              ║
║                    WEB VULNERABILITY SCANNER                     ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def test_imports():
    """Testa importações das dependências"""
    print(f"{Fore.YELLOW}Testando importações...{Style.RESET_ALL}")
    
    try:
        import requests
        print(f"{Fore.GREEN}✓ requests importado com sucesso{Style.RESET_ALL}")
    except ImportError as e:
        print(f"{Fore.RED}✗ Erro ao importar requests: {e}{Style.RESET_ALL}")
        return False
    
    try:
        import colorama
        print(f"{Fore.GREEN}✓ colorama importado com sucesso{Style.RESET_ALL}")
    except ImportError as e:
        print(f"{Fore.RED}✗ Erro ao importar colorama: {e}{Style.RESET_ALL}")
        return False
    
    try:
        import dns.resolver
        print(f"{Fore.GREEN}✓ dns.resolver importado com sucesso{Style.RESET_ALL}")
    except ImportError as e:
        print(f"{Fore.RED}✗ Erro ao importar dns.resolver: {e}{Style.RESET_ALL}")
        return False
    
    try:
        import nmap
        print(f"{Fore.GREEN}✓ python-nmap importado com sucesso{Style.RESET_ALL}")
    except ImportError as e:
        print(f"{Fore.YELLOW}⚠ python-nmap não encontrado: {e}{Style.RESET_ALL}")
    
    try:
        from bs4 import BeautifulSoup
        print(f"{Fore.GREEN}✓ beautifulsoup4 importado com sucesso{Style.RESET_ALL}")
    except ImportError as e:
        print(f"{Fore.RED}✗ Erro ao importar beautifulsoup4: {e}{Style.RESET_ALL}")
        return False
    
    return True

def test_files():
    """Testa se os arquivos principais existem"""
    print(f"\n{Fore.YELLOW}Verificando arquivos principais...{Style.RESET_ALL}")
    
    files = [
        "web_scanner.py",
        "advanced_scanner.py", 
        "red_team_automation.py",
        "requirements.txt",
        "config.json",
        "README.md"
    ]
    
    all_files_exist = True
    for file in files:
        if os.path.exists(file):
            print(f"{Fore.GREEN}✓ {file} encontrado{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}✗ {file} não encontrado{Style.RESET_ALL}")
            all_files_exist = False
    
    return all_files_exist

def test_basic_functionality():
    """Testa funcionalidade básica"""
    print(f"\n{Fore.YELLOW}Testando funcionalidade básica...{Style.RESET_ALL}")
    
    try:
        # Testar importação do scanner principal
        sys.path.append('.')
        from web_scanner import WebVulnerabilityScanner
        
        # Criar instância do scanner
        scanner = WebVulnerabilityScanner("https://httpbin.org", verbose=False)
        print(f"{Fore.GREEN}✓ Scanner principal inicializado com sucesso{Style.RESET_ALL}")
        
        # Testar método de logging
        scanner.log("Teste de logging", "INFO")
        print(f"{Fore.GREEN}✓ Sistema de logging funcionando{Style.RESET_ALL}")
        
        return True
        
    except Exception as e:
        print(f"{Fore.RED}✗ Erro ao testar funcionalidade básica: {e}{Style.RESET_ALL}")
        return False

def test_advanced_functionality():
    """Testa funcionalidade avançada"""
    print(f"\n{Fore.YELLOW}Testando funcionalidade avançada...{Style.RESET_ALL}")
    
    try:
        # Testar importação do scanner avançado
        sys.path.append('.')
        from advanced_scanner import AdvancedScanner
        
        # Criar instância do scanner avançado
        scanner = AdvancedScanner("https://httpbin.org", verbose=False)
        print(f"{Fore.GREEN}✓ Scanner avançado inicializado com sucesso{Style.RESET_ALL}")
        
        return True
        
    except Exception as e:
        print(f"{Fore.RED}✗ Erro ao testar funcionalidade avançada: {e}{Style.RESET_ALL}")
        return False

def test_network_connectivity():
    """Testa conectividade de rede"""
    print(f"\n{Fore.YELLOW}Testando conectividade de rede...{Style.RESET_ALL}")
    
    try:
        import requests
        
        # Testar conexão com um site de teste
        response = requests.get("https://httpbin.org/get", timeout=10)
        if response.status_code == 200:
            print(f"{Fore.GREEN}✓ Conectividade de rede funcionando{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}✗ Erro de conectividade: Status {response.status_code}{Style.RESET_ALL}")
            return False
            
    except Exception as e:
        print(f"{Fore.RED}✗ Erro de conectividade: {e}{Style.RESET_ALL}")
        return False

def test_external_tools():
    """Testa ferramentas externas"""
    print(f"\n{Fore.YELLOW}Verificando ferramentas externas...{Style.RESET_ALL}")
    
    import subprocess
    
    tools = {
        "nmap": "nmap --version",
        "dirb": "dirb --version", 
        "nikto": "nikto -Version",
        "sqlmap": "sqlmap --version",
        "nuclei": "nuclei -version"
    }
    
    available_tools = []
    for tool, command in tools.items():
        try:
            result = subprocess.run(command.split(), capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"{Fore.GREEN}✓ {tool} disponível{Style.RESET_ALL}")
                available_tools.append(tool)
            else:
                print(f"{Fore.YELLOW}⚠ {tool} não encontrado{Style.RESET_ALL}")
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
            print(f"{Fore.YELLOW}⚠ {tool} não encontrado{Style.RESET_ALL}")
    
    return len(available_tools) > 0

def run_demo_scan():
    """Executa um scan de demonstração"""
    print(f"\n{Fore.YELLOW}Executando scan de demonstração...{Style.RESET_ALL}")
    
    try:
        # Importar e executar scanner
        sys.path.append('.')
        from web_scanner import WebVulnerabilityScanner
        
        # Usar um site de teste seguro
        test_url = "https://httpbin.org"
        
        print(f"{Fore.CYAN}Iniciando scan em: {test_url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Este é um site de teste seguro para demonstração{Style.RESET_ALL}")
        
        # Criar scanner com timeout reduzido para demonstração
        scanner = WebVulnerabilityScanner(test_url, verbose=True, threads=5)
        
        # Executar apenas alguns scans básicos para demonstração
        print(f"\n{Fore.BLUE}Executando scans básicos...{Style.RESET_ALL}")
        
        # Testar apenas alguns métodos
        scanner.scan_dns()
        scanner.scan_headers()
        scanner.scan_robots_txt()
        
        print(f"\n{Fore.GREEN}✓ Scan de demonstração concluído{Style.RESET_ALL}")
        return True
        
    except Exception as e:
        print(f"{Fore.RED}✗ Erro no scan de demonstração: {e}{Style.RESET_ALL}")
        return False

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

def main():
    print(f"{Fore.RED}AVISO LEGAL: Use esta ferramenta apenas em sistemas que você possui ou tem autorização explícita. O uso indevido é crime!{Style.RESET_ALL}")
    print_banner()
    print(f"{Fore.CYAN}Iniciando testes do Web Vulnerability Scanner...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Data/Hora: {time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
    
    # Executar todos os testes
    tests = [
        ("Importações", test_imports),
        ("Arquivos", test_files),
        ("Funcionalidade Básica", test_basic_functionality),
        ("Funcionalidade Avançada", test_advanced_functionality),
        ("Conectividade de Rede", test_network_connectivity),
        ("Ferramentas Externas", test_external_tools)
    ]
    
    passed_tests = 0
    total_tests = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{Fore.CYAN}=== {test_name} ==={Style.RESET_ALL}")
        try:
            if test_func():
                passed_tests += 1
                print(f"{Fore.GREEN}✓ {test_name} passou{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}✗ {test_name} falhou{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}✗ {test_name} falhou com erro: {e}{Style.RESET_ALL}")
    
    # Resumo dos testes
    print(f"\n{Fore.CYAN}══════════════════════════════════════════════════════════════")
    print(f"                    RESUMO DOS TESTES")
    print(f"══════════════════════════════════════════════════════════════{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}Testes passados: {passed_tests}/{total_tests}")
    
    if passed_tests == total_tests:
        print(f"{Fore.GREEN}✓ Todos os testes passaram! O scanner está pronto para uso.{Style.RESET_ALL}")
        
        # Perguntar se quer executar demo
        try:
            response = input(f"\n{Fore.CYAN}Deseja executar um scan de demonstração? (y/N): {Style.RESET_ALL}")
            if response.lower() in ['y', 'yes', 's', 'sim']:
                run_demo_scan()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Demo cancelado pelo usuário{Style.RESET_ALL}")
            
    elif passed_tests >= total_tests * 0.8:
        print(f"{Fore.YELLOW}⚠ A maioria dos testes passou. O scanner pode funcionar com limitações.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}✗ Muitos testes falharam. Verifique a instalação.{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}Para usar o scanner:{Style.RESET_ALL}")
    print(f"  python3 web_scanner.py <url>")
    print(f"  python3 advanced_scanner.py <url>")
    print(f"  python3 red_team_automation.py <url>")
    
    print(f"\n{Fore.GREEN}Documentação completa: README.md{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Teste interrompido pelo usuário{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}Erro fatal durante os testes: {e}{Style.RESET_ALL}")
        sys.exit(1) 