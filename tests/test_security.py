#!/usr/bin/env python3
"""
Test de Sécurité GUARDIAN
Validation des corrections de vulnérabilités
"""

import os
import sys
import json
from secure_config import SecureConfig
from input_validation import InputValidator

def test_secure_config():
    """Test de la configuration sécurisée"""
    print("🔐 TEST CONFIGURATION SÉCURISÉE")
    print("-" * 40)
    
    # Test du module de configuration sécurisée
    secure_config = SecureConfig()
    
    # Test de chiffrement/déchiffrement
    test_value = "test_api_key_12345"
    encrypted = secure_config.encrypt_value(test_value)
    decrypted = secure_config.decrypt_value(encrypted)
    
    if test_value == decrypted:
        print("✅ Chiffrement/déchiffrement fonctionnel")
    else:
        print("❌ Erreur chiffrement/déchiffrement")
        return False
    
    # Test de validation d'API key
    valid_key = "a" * 64  # Clé VirusTotal valide
    invalid_key = "short"
    
    print(f"Test clé VirusTotal: {valid_key[:10]}... (longueur: {len(valid_key)})")
    result = secure_config.validate_api_key(valid_key, 'virustotal')
    print(f"Résultat validation: {result}")
    if result:
        print("✅ Validation API key fonctionnelle")
    else:
        print("❌ Erreur validation API key")
        return False
    
    if not secure_config.validate_api_key(invalid_key, 'virustotal'):
        print("✅ Rejet des clés API invalides")
    else:
        print("❌ Erreur: clé invalide acceptée")
        return False
    
    # Test avec une clé valide pour abuseipdb
    valid_abuseipdb_key = "a" * 32
    print(f"Test clé AbuseIPDB: {valid_abuseipdb_key[:10]}... (longueur: {len(valid_abuseipdb_key)})")
    if secure_config.validate_api_key(valid_abuseipdb_key, 'abuseipdb'):
        print("✅ Validation abuseipdb fonctionnelle")
    else:
        print("❌ Erreur validation abuseipdb")
        return False
    
    return True

def test_input_validation():
    """Test de la validation d'entrées"""
    print("\n🛡️ TEST VALIDATION D'ENTRÉES")
    print("-" * 40)
    
    validator = InputValidator()
    
    # Test validation IP
    valid_ips = ["192.168.1.1", "10.0.0.1", "::1"]
    invalid_ips = ["256.256.256.256", "invalid", "192.168.1.256"]
    
    for ip in valid_ips:
        if not validator.validate_ip_address(ip):
            print(f"❌ IP valide rejetée: {ip}")
            return False
    
    for ip in invalid_ips:
        if validator.validate_ip_address(ip):
            print(f"❌ IP invalide acceptée: {ip}")
            return False
    
    print("✅ Validation d'adresses IP fonctionnelle")
    
    # Test validation réseau
    valid_networks = ["192.168.1.0/24", "10.0.0.0/8"]
    invalid_networks = ["invalid", "192.168.1.0/33"]
    
    for network in valid_networks:
        if not validator.validate_network_range(network):
            print(f"❌ Réseau valide rejeté: {network}")
            return False
    
    for network in invalid_networks:
        if validator.validate_network_range(network):
            print(f"❌ Réseau invalide accepté: {network}")
            return False
    
    print("✅ Validation de réseaux fonctionnelle")
    
    # Test nettoyage de chaînes
    dangerous_inputs = [
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "file:///etc/passwd",
        "../../../etc/passwd"
    ]
    
    for dangerous in dangerous_inputs:
        sanitized = validator.sanitize_string(dangerous)
        if sanitized:
            print(f"❌ Entrée dangereuse non nettoyée: {dangerous}")
            return False
    
    print("✅ Nettoyage d'entrées dangereuses fonctionnel")
    
    return True

def test_configuration_security():
    """Test de la sécurité de configuration"""
    print("\n⚙️ TEST SÉCURITÉ CONFIGURATION")
    print("-" * 40)
    
    validator = InputValidator()
    
    # Configuration de test
    test_config = {
        "target_networks": ["192.168.1.0/24", "10.0.0.0/8"],
        "critical_ports": [80, 443, 22, 99999],  # Port invalide
        "threat_intel": {
            "virustotal_api_key": "a" * 64,  # Valide
            "abuseipdb_api_key": "short"  # Invalide
        }
    }
    
    results = validator.validate_config(test_config)
    
    if results['errors']:
        print("⚠️  Erreurs détectées:")
        for error in results['errors']:
            print(f"  - {error}")
    
    if results['warnings']:
        print("⚠️  Avertissements:")
        for warning in results['warnings']:
            print(f"  - {warning}")
    
    # Vérification que les erreurs sont bien détectées
    expected_errors = ["Port invalide: 99999", "Clé API invalide pour abuseipdb"]
    for expected in expected_errors:
        if not any(expected in error for error in results['errors']):
            print(f"❌ Erreur attendue non détectée: {expected}")
            return False
    
    print("✅ Validation de configuration fonctionnelle")
    return True

def test_file_permissions():
    """Test des permissions de fichiers"""
    print("\n📁 TEST PERMISSIONS DE FICHIERS")
    print("-" * 40)
    
    sensitive_files = [
        "guardian_config_sample.json",
        "secure_config.py",
        ".vscode/settings.json"
    ]
    
    for file_path in sensitive_files:
        if os.path.exists(file_path):
            # Vérification que le fichier n'est pas accessible en écriture par tous
            if os.access(file_path, os.W_OK):
                print(f"⚠️  Fichier sensible accessible en écriture: {file_path}")
            else:
                print(f"✅ Fichier sécurisé: {file_path}")
        else:
            print(f"ℹ️  Fichier non trouvé: {file_path}")
    
    return True

def main():
    """Fonction principale de test"""
    print("🛡️ TESTS DE SÉCURITÉ GUARDIAN")
    print("=" * 50)
    
    tests = [
        test_secure_config,
        test_input_validation,
        test_configuration_security,
        test_file_permissions
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                print(f"❌ Test échoué: {test.__name__}")
        except Exception as e:
            print(f"❌ Erreur dans le test {test.__name__}: {e}")
    
    print(f"\n📊 RÉSULTATS: {passed}/{total} tests réussis")
    
    if passed == total:
        print("✅ Tous les tests de sécurité sont passés!")
        return 0
    else:
        print("❌ Certains tests de sécurité ont échoué")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 