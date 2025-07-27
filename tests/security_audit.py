#!/usr/bin/env python3
"""
Audit de Sécurité GUARDIAN - Analyse DevSecOps
"""

import os
import json
import re
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple

class SecurityAuditor:
    def __init__(self):
        self.vulnerabilities = []
        self.recommendations = []
        
    def audit_file_permissions(self) -> List[str]:
        """Audit des permissions de fichiers"""
        issues = []
        
        # Vérification des fichiers sensibles
        sensitive_files = [
            "guardian_config_sample.json",
            "guardian.py",
            ".vscode/settings.json"
        ]
        
        for file_path in sensitive_files:
            if os.path.exists(file_path):
                # Vérification des permissions (simulation)
                issues.append(f"⚠️  Fichier sensible: {file_path}")
                
        return issues
    
    def audit_code_injection(self, file_path: str) -> List[str]:
        """Audit des vulnérabilités d'injection de code"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Recherche de patterns dangereux
            dangerous_patterns = [
                r'eval\s*\(',
                r'exec\s*\(',
                r'os\.system\s*\(',
                r'subprocess\.call\s*\(',
                r'__import__\s*\(',
                r'input\s*\(',
                r'raw_input\s*\('
            ]
            
            for pattern in dangerous_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    issues.append(f"🚨 Injection potentielle: {pattern} dans {file_path}")
                    
        except Exception as e:
            issues.append(f"❌ Erreur lecture {file_path}: {e}")
            
        return issues
    
    def audit_api_keys(self, file_path: str) -> List[str]:
        """Audit des clés API exposées"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Recherche de clés API potentielles
            api_key_patterns = [
                r'api_key["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'api_key["\']?\s*[:=]\s*[^"\s]+',
                r'token["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'password["\']?\s*[:=]\s*["\'][^"\']+["\']',
                r'secret["\']?\s*[:=]\s*["\'][^"\']+["\']'
            ]
            
            for pattern in api_key_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    issues.append(f"🔑 Clé API potentielle trouvée dans {file_path}")
                    
        except Exception as e:
            issues.append(f"❌ Erreur lecture {file_path}: {e}")
            
        return issues
    
    def audit_network_security(self, file_path: str) -> List[str]:
        """Audit de la sécurité réseau"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Recherche de configurations réseau dangereuses
            network_issues = [
                r'0\.0\.0\.0',  # Écoute sur toutes les interfaces
                r'0\.0\.0\.0/0',  # Toutes les IPs
                r'allow_all',  # Autorisation générale
                r'permit any',  # Permettre tout
                r'disable.*firewall',  # Désactiver firewall
                r'disable.*security'  # Désactiver sécurité
            ]
            
            for pattern in network_issues:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    issues.append(f"🌐 Configuration réseau dangereuse: {pattern} dans {file_path}")
                    
        except Exception as e:
            issues.append(f"❌ Erreur lecture {file_path}: {e}")
            
        return issues
    
    def audit_file_operations(self, file_path: str) -> List[str]:
        """Audit des opérations de fichiers"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Recherche d'opérations de fichiers dangereuses
            file_operations = [
                r'open\s*\([^)]*["\']/',  # Ouverture de fichiers absolus
                r'open\s*\([^)]*["\']\.\.',  # Path traversal
                r'os\.remove\s*\(',
                r'os\.unlink\s*\(',
                r'shutil\.rmtree\s*\(',
                r'os\.system\s*\([^)]*rm',  # Suppression système
                r'subprocess\.call\s*\([^)]*rm'  # Suppression via subprocess
            ]
            
            for pattern in file_operations:
                matches = re.findall(pattern, content)
                if matches:
                    issues.append(f"📁 Opération fichier dangereuse: {pattern} dans {file_path}")
                    
        except Exception as e:
            issues.append(f"❌ Erreur lecture {file_path}: {e}")
            
        return issues
    
    def audit_authentication(self, file_path: str) -> List[str]:
        """Audit de l'authentification"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Recherche de problèmes d'authentification
            auth_issues = [
                r'admin.*password',
                r'root.*password',
                r'default.*password',
                r'hardcoded.*password',
                r'password.*=.*["\'][^"\']+["\']',
                r'username.*=.*["\'][^"\']+["\']'
            ]
            
            for pattern in auth_issues:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    issues.append(f"🔐 Problème d'authentification: {pattern} dans {file_path}")
                    
        except Exception as e:
            issues.append(f"❌ Erreur lecture {file_path}: {e}")
            
        return issues
    
    def audit_encryption(self, file_path: str) -> List[str]:
        """Audit du chiffrement"""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Recherche de problèmes de chiffrement
            crypto_issues = [
                r'MD5',
                r'SHA1',
                r'DES',
                r'RC4',
                r'weak.*crypto',
                r'broken.*crypto'
            ]
            
            for pattern in crypto_issues:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    issues.append(f"🔒 Algorithme de chiffrement faible: {pattern} dans {file_path}")
                    
        except Exception as e:
            issues.append(f"❌ Erreur lecture {file_path}: {e}")
            
        return issues
    
    def audit_entire_project(self) -> Dict:
        """Audit complet du projet"""
        print("🔍 AUDIT DE SÉCURITÉ GUARDIAN")
        print("=" * 50)
        
        all_issues = {
            'file_permissions': [],
            'code_injection': [],
            'api_keys': [],
            'network_security': [],
            'file_operations': [],
            'authentication': [],
            'encryption': []
        }
        
        # Fichiers à auditer
        files_to_audit = [
            'guardian.py',
            'guardian_config_sample.json',
            'install_dependencies.py',
            'test_simple_features.py',
            'demo_advanced_features.py'
        ]
        
        # Audit des permissions
        all_issues['file_permissions'] = self.audit_file_permissions()
        
        # Audit de chaque fichier
        for file_path in files_to_audit:
            if os.path.exists(file_path):
                all_issues['code_injection'].extend(self.audit_code_injection(file_path))
                all_issues['api_keys'].extend(self.audit_api_keys(file_path))
                all_issues['network_security'].extend(self.audit_network_security(file_path))
                all_issues['file_operations'].extend(self.audit_file_operations(file_path))
                all_issues['authentication'].extend(self.audit_authentication(file_path))
                all_issues['encryption'].extend(self.audit_encryption(file_path))
        
        return all_issues
    
    def generate_security_report(self, issues: Dict) -> str:
        """Génère un rapport de sécurité"""
        report = []
        report.append("🛡️ RAPPORT DE SÉCURITÉ GUARDIAN")
        report.append("=" * 50)
        
        total_issues = 0
        
        for category, category_issues in issues.items():
            if category_issues:
                report.append(f"\n📋 {category.upper().replace('_', ' ')}:")
                for issue in category_issues:
                    report.append(f"  {issue}")
                total_issues += len(category_issues)
        
        report.append(f"\n📊 RÉSUMÉ:")
        report.append(f"  - Total d'issues: {total_issues}")
        
        if total_issues == 0:
            report.append("  ✅ Aucune vulnérabilité critique détectée")
        elif total_issues < 5:
            report.append("  ⚠️  Quelques problèmes mineurs détectés")
        else:
            report.append("  🚨 Vulnérabilités critiques détectées")
        
        report.append("\n🔒 RECOMMANDATIONS DE SÉCURITÉ:")
        report.append("  1. Utilisez des variables d'environnement pour les clés API")
        report.append("  2. Validez toutes les entrées utilisateur")
        report.append("  3. Utilisez des algorithmes de chiffrement forts")
        report.append("  4. Limitez les permissions de fichiers")
        report.append("  5. Implémentez une authentification robuste")
        report.append("  6. Utilisez HTTPS pour toutes les communications")
        report.append("  7. Effectuez des audits de sécurité réguliers")
        
        return "\n".join(report)

def main():
    """Fonction principale"""
    auditor = SecurityAuditor()
    
    # Audit complet
    issues = auditor.audit_entire_project()
    
    # Génération du rapport
    report = auditor.generate_security_report(issues)
    
    # Affichage du rapport
    print(report)
    
    # Sauvegarde du rapport
    with open("security_audit_report.txt", "w", encoding="utf-8") as f:
        f.write(report)
    
    print(f"\n📄 Rapport sauvegardé dans: security_audit_report.txt")

if __name__ == "__main__":
    main() 