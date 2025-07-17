#!/bin/bash

# Web Vulnerability Scanner - Red Team Tool
# Script de Instalação Automatizada

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    WEB VULNERABILITY SCANNER                    ║"
echo "║                        RED TEAM TOOL                            ║"
echo "║                    INSTALADOR AUTOMÁTICO                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Função para log
log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
}

# Verificar se é root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        warning "Este script não deve ser executado como root"
        read -p "Deseja continuar mesmo assim? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Detectar sistema operacional
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            OS="debian"
        elif [ -f /etc/redhat-release ]; then
            OS="redhat"
        elif [ -f /etc/arch-release ]; then
            OS="arch"
        else
            OS="linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        error "Sistema operacional não suportado: $OSTYPE"
        exit 1
    fi
    
    log "Sistema operacional detectado: $OS"
}

# Verificar Python
check_python() {
    log "Verificando Python..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        success "Python $PYTHON_VERSION encontrado"
    else
        error "Python 3 não encontrado"
        log "Instalando Python 3..."
        
        case $OS in
            "debian")
                sudo apt update
                sudo apt install -y python3 python3-pip
                ;;
            "redhat")
                sudo yum install -y python3 python3-pip
                ;;
            "arch")
                sudo pacman -S --noconfirm python python-pip
                ;;
            "macos")
                if command -v brew &> /dev/null; then
                    brew install python3
                else
                    error "Homebrew não encontrado. Instale o Homebrew primeiro."
                    exit 1
                fi
                ;;
        esac
    fi
}

# Instalar dependências Python
install_python_deps() {
    log "Instalando dependências Python..."
    
    if [ -f "requirements.txt" ]; then
        pip3 install -r requirements.txt
        success "Dependências Python instaladas"
    else
        error "Arquivo requirements.txt não encontrado"
        exit 1
    fi
}

# Instalar ferramentas externas
install_external_tools() {
    log "Instalando ferramentas externas..."
    
    case $OS in
        "debian")
            log "Instalando ferramentas via apt..."
            sudo apt update
            sudo apt install -y nmap dirb nikto
            
            # Instalar SQLMap
            if ! command -v sqlmap &> /dev/null; then
                log "Instalando SQLMap..."
                sudo apt install -y sqlmap
            fi
            
            # Instalar Nuclei
            if ! command -v nuclei &> /dev/null; then
                log "Instalando Nuclei..."
                curl -sfL https://raw.githubusercontent.com/projectdiscovery/nuclei/master/v2/cmd/nuclei/install.sh | sh -s -- -b /usr/local/bin
            fi
            ;;
            
        "redhat")
            log "Instalando ferramentas via yum..."
            sudo yum install -y nmap
            
            # Instalar outras ferramentas via pip ou download manual
            if ! command -v dirb &> /dev/null; then
                warning "Dirb não disponível via yum. Instale manualmente."
            fi
            
            if ! command -v nikto &> /dev/null; then
                warning "Nikto não disponível via yum. Instale manualmente."
            fi
            ;;
            
        "arch")
            log "Instalando ferramentas via pacman..."
            sudo pacman -S --noconfirm nmap
            
            # Instalar outras ferramentas via AUR ou pip
            if ! command -v dirb &> /dev/null; then
                warning "Dirb não disponível via pacman. Instale manualmente."
            fi
            
            if ! command -v nikto &> /dev/null; then
                warning "Nikto não disponível via pacman. Instale manualmente."
            fi
            ;;
            
        "macos")
            if command -v brew &> /dev/null; then
                log "Instalando ferramentas via Homebrew..."
                brew install nmap
                
                # Instalar outras ferramentas via pip
                pip3 install sqlmap
                
                # Instalar Nuclei
                if ! command -v nuclei &> /dev/null; then
                    log "Instalando Nuclei..."
                    brew install nuclei
                fi
            else
                error "Homebrew não encontrado. Instale o Homebrew primeiro."
                exit 1
            fi
            ;;
    esac
}

# Configurar permissões
setup_permissions() {
    log "Configurando permissões..."
    
    chmod +x web_scanner.py
    chmod +x advanced_scanner.py
    chmod +x red_team_automation.py
    
    success "Permissões configuradas"
}

# Criar diretório de relatórios
create_directories() {
    log "Criando diretórios..."
    
    mkdir -p reports
    mkdir -p logs
    
    success "Diretórios criados"
}

# Verificar instalação
verify_installation() {
    log "Verificando instalação..."
    
    # Verificar arquivos principais
    files=("web_scanner.py" "advanced_scanner.py" "red_team_automation.py" "requirements.txt")
    for file in "${files[@]}"; do
        if [ -f "$file" ]; then
            success "Arquivo $file encontrado"
        else
            error "Arquivo $file não encontrado"
        fi
    done
    
    # Verificar ferramentas externas
    tools=("nmap" "python3" "pip3")
    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            success "Ferramenta $tool encontrada"
        else
            warning "Ferramenta $tool não encontrada"
        fi
    done
    
    # Testar scanner
    log "Testando scanner..."
    if python3 -c "import requests, colorama, dns.resolver" 2>/dev/null; then
        success "Dependências Python funcionando"
    else
        error "Problema com dependências Python"
    fi
}

# Mostrar informações pós-instalação
show_post_install_info() {
    echo
    echo -e "${GREEN}══════════════════════════════════════════════════════════════"
    echo "                    INSTALAÇÃO CONCLUÍDA"
    echo "══════════════════════════════════════════════════════════════${NC}"
    echo
    echo -e "${YELLOW}Próximos passos:${NC}"
    echo "1. Teste o scanner:"
    echo "   python3 web_scanner.py https://example.com"
    echo
    echo "2. Execute o scanner avançado:"
    echo "   python3 advanced_scanner.py https://example.com"
    echo
    echo "3. Use a automação completa:"
    echo "   python3 red_team_automation.py https://example.com"
    echo
    echo "4. Verifique as ferramentas externas:"
    echo "   python3 red_team_automation.py --check-tools"
    echo
    echo -e "${RED}⚠️  AVISO LEGAL:${NC}"
    echo "Use esta ferramenta apenas em sistemas que você possui ou tem autorização explícita."
    echo "O uso inadequado pode resultar em consequências legais."
    echo
    echo -e "${GREEN}Documentação completa disponível em: README.md${NC}"
}

# Função principal
main() {
    check_root
    detect_os
    check_python
    install_python_deps
    install_external_tools
    setup_permissions
    create_directories
    verify_installation
    show_post_install_info
}

# Executar função principal
main "$@" 