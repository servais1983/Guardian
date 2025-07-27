#!/usr/bin/env python3
"""
Module de Configuration Sécurisée pour GUARDIAN
Gestion sécurisée des variables d'environnement et clés API
"""

import os
import json
import base64
import hashlib
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet  # type: ignore
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore
import secrets

class SecureConfig:
    """Gestionnaire de configuration sécurisée"""
    
    def __init__(self, master_key: Optional[str] = None):
        """Initialise le gestionnaire de configuration sécurisée"""
        self.master_key = master_key or os.getenv('GUARDIAN_MASTER_KEY')
        self._fernet = None
        self._initialize_encryption()
    
    def _initialize_encryption(self):
        """Initialise le chiffrement Fernet"""
        if not self.master_key:
            # Génère une clé maître si elle n'existe pas
            self.master_key = secrets.token_urlsafe(32)
            print(f"🔑 Clé maître générée: {self.master_key}")
            print("⚠️  Sauvegardez cette clé dans une variable d'environnement GUARDIAN_MASTER_KEY")
        
        # Génère une clé de chiffrement à partir de la clé maître
        salt = b'guardian_salt_2024'  # Salt fixe pour la démo
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_key.encode()))
        self._fernet = Fernet(key)
    
    def encrypt_value(self, value: str) -> str:
        """Chiffre une valeur"""
        if not self._fernet:
            raise ValueError("Chiffrement non initialisé")
        return self._fernet.encrypt(value.encode()).decode()
    
    def decrypt_value(self, encrypted_value: str) -> str:
        """Déchiffre une valeur"""
        if not self._fernet:
            raise ValueError("Chiffrement non initialisé")
        return self._fernet.decrypt(encrypted_value.encode()).decode()
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Récupère une clé API de manière sécurisée"""
        # Variables d'environnement prioritaires
        env_var = f"GUARDIAN_{service.upper()}_API_KEY"
        api_key = os.getenv(env_var)
        
        if api_key:
            return api_key
        
        # Fallback vers le fichier de configuration chiffré
        config_file = ".guardian_secure_config.json"
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    encrypted_config = json.load(f)
                
                if service in encrypted_config:
                    return self.decrypt_value(encrypted_config[service])
            except Exception as e:
                print(f"⚠️  Erreur lecture config chiffrée: {e}")
        
        return None
    
    def set_api_key(self, service: str, api_key: str):
        """Définit une clé API de manière sécurisée"""
        # Sauvegarde dans un fichier chiffré
        config_file = ".guardian_secure_config.json"
        
        try:
            # Charge la configuration existante
            encrypted_config = {}
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    encrypted_config = json.load(f)
            
            # Ajoute la nouvelle clé chiffrée
            encrypted_config[service] = self.encrypt_value(api_key)
            
            # Sauvegarde
            with open(config_file, 'w') as f:
                json.dump(encrypted_config, f, indent=2)
            
            print(f"✅ Clé API {service} sauvegardée de manière sécurisée")
            
        except Exception as e:
            print(f"❌ Erreur sauvegarde clé API: {e}")
    
    def validate_api_key(self, service: str, api_key: str) -> bool:
        """Valide une clé API"""
        if not api_key:
            return False
        
        # Validation basique selon le service
        validations = {
            'virustotal': lambda k: len(k) == 64 and all(c.isalnum() for c in k),
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
        return len(api_key) >= 16
    
    def get_secure_config(self) -> Dict[str, Any]:
        """Récupère la configuration sécurisée"""
        config = {
            'threat_intel': {
                'virustotal_api_key': self.get_api_key('virustotal'),
                'abuseipdb_api_key': self.get_api_key('abuseipdb'),
                'shodan_api_key': self.get_api_key('shodan'),
                'otx_api_key': self.get_api_key('otx'),
                'urlvoid_api_key': self.get_api_key('urlvoid'),
                'hybrid_analysis_api_key': self.get_api_key('hybrid_analysis')
            },
            'siem': {
                'splunk_hec_token': self.get_api_key('splunk'),
                'elasticsearch_api_key': self.get_api_key('elasticsearch')
            },
            'dashboard': {
                'grafana_api_key': self.get_api_key('grafana'),
                'influxdb_token': self.get_api_key('influxdb')
            }
        }
        
        return config
    
    def create_env_template(self):
        """Crée un template de fichier .env"""
        template = """# GUARDIAN - Variables d'Environnement Sécurisées
# Copiez ce fichier vers .env et remplissez vos clés API

# Clé maître pour le chiffrement (générée automatiquement si absente)
GUARDIAN_MASTER_KEY=votre_clé_maître_ici

# Threat Intelligence APIs
GUARDIAN_VIRUSTOTAL_API_KEY=votre_clé_virustotal
GUARDIAN_ABUSEIPDB_API_KEY=votre_clé_abuseipdb
GUARDIAN_SHODAN_API_KEY=votre_clé_shodan
GUARDIAN_OTX_API_KEY=votre_clé_otx
GUARDIAN_URLVOID_API_KEY=votre_clé_urlvoid
GUARDIAN_HYBRID_ANALYSIS_API_KEY=votre_clé_hybrid_analysis

# SIEM Integrations
GUARDIAN_SPLUNK_API_KEY=votre_clé_splunk
GUARDIAN_ELASTICSEARCH_API_KEY=votre_clé_elasticsearch

# Dashboard Integrations
GUARDIAN_GRAFANA_API_KEY=votre_clé_grafana
GUARDIAN_INFLUXDB_TOKEN=votre_token_influxdb

# SMTP Configuration
GUARDIAN_SMTP_USERNAME=votre_email
GUARDIAN_SMTP_PASSWORD=votre_mot_de_passe_app

# Webhooks
GUARDIAN_SLACK_WEBHOOK=votre_webhook_slack
GUARDIAN_TEAMS_WEBHOOK=votre_webhook_teams
"""
        
        with open('.env.template', 'w') as f:
            f.write(template)
        
        print("✅ Template .env créé: .env.template")
        print("📝 Copiez vers .env et remplissez vos clés API")

def load_dotenv():
    """Charge les variables d'environnement depuis .env"""
    env_file = '.env'
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key] = value

# Charge les variables d'environnement au démarrage
load_dotenv()

# Instance globale
secure_config = SecureConfig() 