#!/usr/bin/env python3
"""
Serveur Prometheus pour GUARDIAN
Métriques temps réel
"""

import asyncio
import time
from prometheus_client import start_http_server, Counter, Gauge, Histogram, Summary  # type: ignore
from typing import Dict, Any

class GuardianMetrics:
    """Métriques Prometheus pour GUARDIAN"""
    
    def __init__(self):
        # Compteurs
        self.scans_total = Counter('guardian_scans_total', 'Nombre total de scans')
        self.alerts_total = Counter('guardian_alerts_total', 'Nombre total d\'alertes', ['severity', 'category'])
        self.services_discovered = Counter('guardian_services_discovered', 'Services découverts', ['host', 'port', 'service'])
        
        # Gauges
        self.active_services = Gauge('guardian_active_services', 'Services actifs par host', ['host'])
        self.vulnerability_score = Gauge('guardian_vulnerability_score', 'Score de vulnérabilité', ['host', 'port'])
        self.threat_intel_score = Gauge('guardian_threat_intel_score', 'Score Threat Intelligence', ['host'])
        self.ssl_cert_days = Gauge('guardian_ssl_cert_days_to_expiry', 'Jours avant expiration SSL', ['host', 'port'])
        
        # Histogrammes
        self.scan_duration = Histogram('guardian_scan_duration_seconds', 'Durée des scans')
        self.threat_intel_duration = Histogram('guardian_threat_intel_duration_seconds', 'Durée des requêtes Threat Intel')
        
        # Résumés
        self.alert_processing_time = Summary('guardian_alert_processing_seconds', 'Temps de traitement des alertes')
        
        # Métriques personnalisées
        self.network_coverage = Gauge('guardian_network_coverage_percent', 'Couverture réseau en pourcentage')
        self.critical_ports_open = Gauge('guardian_critical_ports_open', 'Ports critiques ouverts', ['host'])
        self.new_services_detected = Counter('guardian_new_services_detected', 'Nouveaux services détectés')
        self.changed_services = Counter('guardian_changed_services', 'Services modifiés')
        self.removed_services = Counter('guardian_removed_services', 'Services supprimés')
        
        # Métriques SOAR
        self.playbooks_executed = Counter('guardian_playbooks_executed', 'Playbooks exécutés', ['playbook_name'])
        self.tickets_created = Counter('guardian_tickets_created', 'Tickets créés')
        self.notifications_sent = Counter('guardian_notifications_sent', 'Notifications envoyées', ['channel'])
        
        # Métriques SIEM
        self.siem_exports = Counter('guardian_siem_exports', 'Exports SIEM', ['format'])
        self.siem_export_errors = Counter('guardian_siem_export_errors', 'Erreurs d\'export SIEM')
        
    def record_scan(self, network: str, duration: float, services_found: int):
        """Enregistre un scan"""
        self.scans_total.inc()
        self.scan_duration.observe(duration)
        
    def record_service_discovery(self, host: str, port: int, service: str):
        """Enregistre la découverte d'un service"""
        self.services_discovered.labels(host=host, port=str(port), service=service).inc()
        
    def record_alert(self, severity: str, category: str):
        """Enregistre une alerte"""
        self.alerts_total.labels(severity=severity, category=category).inc()
        
    def update_vulnerability_score(self, host: str, port: int, score: float):
        """Met à jour le score de vulnérabilité"""
        self.vulnerability_score.labels(host=host, port=str(port)).set(score)
        
    def update_threat_intel_score(self, host: str, score: float):
        """Met à jour le score Threat Intelligence"""
        self.threat_intel_score.labels(host=host).set(score)
        
    def update_ssl_cert_days(self, host: str, port: int, days: int):
        """Met à jour les jours avant expiration SSL"""
        self.ssl_cert_days.labels(host=host, port=str(port)).set(days)
        
    def record_playbook_execution(self, playbook_name: str):
        """Enregistre l'exécution d'un playbook"""
        self.playbooks_executed.labels(playbook_name=playbook_name).inc()
        
    def record_ticket_creation(self):
        """Enregistre la création d'un ticket"""
        self.tickets_created.inc()
        
    def record_notification(self, channel: str):
        """Enregistre l'envoi d'une notification"""
        self.notifications_sent.labels(channel=channel).inc()
        
    def record_siem_export(self, format_name: str):
        """Enregistre un export SIEM"""
        self.siem_exports.labels(format=format_name).inc()
        
    def record_siem_export_error(self):
        """Enregistre une erreur d'export SIEM"""
        self.siem_export_errors.inc()

# Instance globale
metrics = GuardianMetrics()

def start_prometheus_server(port: int = 8000):
    """Démarre le serveur Prometheus"""
    try:
        start_http_server(port)
        print(f"📊 Serveur Prometheus démarré sur le port {port}")
        print(f"📈 Métriques disponibles sur: http://localhost:{port}/metrics")
        return True
    except Exception as e:
        print(f"❌ Erreur démarrage Prometheus: {e}")
        return False 