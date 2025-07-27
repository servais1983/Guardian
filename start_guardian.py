#!/usr/bin/env python3
"""
Script de Démarrage Sécurisé GUARDIAN
"""

import os
import sys
from pathlib import Path

def check_security():
    """Vérifie la sécurité avant le démarrage"""
    print("🔒 VÉRIFICATION DE SÉCURITÉ")
    
    # Vérification des fichiers sensibles
    sensitive_files = [
        ".env",
        ".guardian_secure_config.json"
    ]
    
    for file_path in sensitive_files:
        if os.path.exists(file_path):
            print(f"✅ {file_path} trouvé")
        else:
            print(f"⚠️  {file_path} manquant - Créez votre configuration")
    
    # Vérification des permissions
    if os.access("guardian.py", os.R_OK):
        print("✅ Permissions de lecture OK")
    else:
        print("❌ Problème de permissions")
        return False
    
    return True

def main():
    """Point d'entrée principal"""
    print("🛡️  GUARDIAN - Démarrage Sécurisé")
    print("=" * 40)
    
    if not check_security():
        print("❌ Échec de la vérification de sécurité")
        sys.exit(1)
    
    print("✅ Vérifications de sécurité passées")
    print("🚀 Démarrage de GUARDIAN...")
    
    # Import et exécution de GUARDIAN
    try:
        from guardian import main as guardian_main
        import asyncio
        asyncio.run(guardian_main())
    except ImportError as e:
        print(f"❌ Erreur d'import: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Erreur d'exécution: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
