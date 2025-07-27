#!/usr/bin/env python3
"""
Module de Validation d'Entrées Sécurisée pour GUARDIAN
Protection contre les injections et attaques
"""

import re
import ipaddress
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

class InputValidator:
    """Validateur d'entrées sécurisé"""
    
    def __init__(self):
        # Patterns dangereux
        self.dangerous_patterns = [
            r'<script.*?>.*?</script>',  # XSS
            r'javascript:',  # JavaScript injection
            r'vbscript:',  # VBScript injection
            r'data:',  # Data URI injection
            r'file:',  # File protocol injection
            r'ftp:',  # FTP injection
            r'gopher:',  # Gopher injection
            r'ldap:',  # LDAP injection
            r'ldaps:',  # LDAPS injection
            r'php:',  # PHP injection
            r'asp:',  # ASP injection
            r'jsp:',  # JSP injection
            r'exec\s*\(',  # Command execution
            r'eval\s*\(',  # Code evaluation
            r'system\s*\(',  # System calls
            r'os\.system',  # OS system calls
            r'subprocess',  # Subprocess calls
            r'__import__',  # Dynamic imports
            r'input\s*\(',  # Input function
            r'raw_input',  # Raw input
            r'open\s*\([^)]*\.\.',  # Path traversal
            r'\.\./',  # Directory traversal
            r'\.\.\\',  # Windows path traversal
        ]
        
        # Compilation des patterns
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.dangerous_patterns]
    
    def validate_ip_address(self, ip: str) -> bool:
        """Valide une adresse IP"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def validate_network_range(self, network: str) -> bool:
        """Valide une plage réseau"""
        try:
            ipaddress.ip_network(network, strict=False)
            return True
        except ValueError:
            return False
    
    def validate_port(self, port: int) -> bool:
        """Valide un numéro de port"""
        return 1 <= port <= 65535
    
    def validate_url(self, url: str) -> bool:
        """Valide une URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def sanitize_string(self, text: str) -> str:
        """Nettoie une chaîne de caractères"""
        if not text:
            return ""
        
        # Vérification des patterns dangereux en premier
        for pattern in self.compiled_patterns:
            if pattern.search(text):
                return ""  # Retourne chaîne vide si dangereux
        
        # Suppression des caractères dangereux
        dangerous_chars = ['<', '>', '"', "'", '&', ';', '|', '`', '$', '(', ')', '{', '}']
        for char in dangerous_chars:
            text = text.replace(char, '')
        
        return text.strip()
    
    def validate_api_key(self, api_key: str, service: str) -> bool:
        """Valide une clé API"""
        if not api_key:
            return False
        
        # Validation selon le service
        validations = {
            'virustotal': lambda k: len(k) == 64 and k.isalnum(),
            'abuseipdb': lambda k: len(k) >= 32,
            'shodan': lambda k: len(k) >= 32,
            'otx': lambda k: len(k) >= 32,
            'urlvoid': lambda k: len(k) >= 32,
            'hybrid_analysis': lambda k: len(k) >= 32
        }
        
        validator = validations.get(service.lower())
        if validator:
            return validator(api_key)
        
        # Validation générique
        return len(api_key) >= 16 and not any(char in api_key for char in ['<', '>', '"', "'", '&'])
    
    def validate_config(self, config: Dict[str, Any]) -> Dict[str, List[str]]:
        """Valide une configuration complète"""
        errors = []
        warnings = []
        
        # Validation des réseaux cibles
        if 'target_networks' in config:
            for network in config['target_networks']:
                if not self.validate_network_range(network):
                    errors.append(f"Plage réseau invalide: {network}")
                elif network == "0.0.0.0/0":
                    warnings.append(f"Plage réseau trop large: {network}")
        
        # Validation des ports critiques
        if 'critical_ports' in config:
            for port in config['critical_ports']:
                if not self.validate_port(port):
                    errors.append(f"Port invalide: {port}")
        
        # Validation des clés API
        if 'threat_intel' in config:
            ti_config = config['threat_intel']
            for key_name, api_key in ti_config.items():
                if 'api_key' in key_name and api_key:
                    service = key_name.replace('_api_key', '')
                    if not self.validate_api_key(api_key, service):
                        errors.append(f"Clé API invalide pour {service}")
        
        return {'errors': errors, 'warnings': warnings}
    
    def validate_scan_targets(self, targets: List[str]) -> Dict[str, List[str]]:
        """Valide les cibles de scan"""
        errors = []
        warnings = []
        
        for target in targets:
            # Validation IP
            if self.validate_ip_address(target):
                continue
            
            # Validation plage réseau
            if self.validate_network_range(target):
                if target == "0.0.0.0/0":
                    warnings.append(f"Plage réseau trop large: {target}")
                continue
            
            # Validation hostname
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
                continue
            
            errors.append(f"Cible invalide: {target}")
        
        return {'errors': errors, 'warnings': warnings}

# Instance globale
validator = InputValidator() 