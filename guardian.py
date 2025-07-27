#!/usr/bin/env python3
"""
GUARDIAN - Graphical User Attack Reconnaissance Defense Intelligence & Analysis Network
Version: 2.0
"""

import asyncio
import json
import logging
import socket
import ssl
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import hashlib
import aiohttp  # type: ignore
from concurrent.futures import ThreadPoolExecutor

# Configuration des imports avec gestion d'erreurs
try:
    import nmap  # type: ignore
except ImportError:
    print("❌ Erreur: python-nmap requis. Installez avec: pip install python-nmap")
    exit(1)

try:
    import requests  # type: ignore
except ImportError:
    print("❌ Erreur: requests requis. Installez avec: pip install requests")
    exit(1)

try:
    from cryptography import x509  # type: ignore
    from cryptography.hazmat.backends import default_backend  # type: ignore
except ImportError:
    print("❌ Erreur: cryptography requis. Installez avec: pip install cryptography")
    exit(1)

# Configuration avancée
@dataclass
class ThreatIntelConfig:
    virustotal_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    use_malwarebazaar: bool = True
    use_threatfox: bool = True
    cache_ttl: int = 24

@dataclass
class SiemConfig:
    enabled: bool = False
    export_format: str = "json"
    export_directory: str = "./siem_exports"
    min_severity_level: str = "MEDIUM"

@dataclass
class DashboardConfig:
    enabled: bool = False
    prometheus_enabled: bool = False
    prometheus_port: int = 8000

@dataclass
class SoarConfig:
    enabled: bool = False
    slack_webhook: Optional[str] = None
    teams_webhook: Optional[str] = None
    auto_create_tickets: bool = True
    auto_notify_teams: bool = True

@dataclass
class Config:
    target_networks: List[str]
    critical_ports: List[int]
    scan_interval: int
    baseline_file: str
    log_file: str
    threat_intel: ThreatIntelConfig
    siem: SiemConfig
    dashboard: DashboardConfig
    soar: SoarConfig

@dataclass
class ThreatIntelData:
    source: str
    ip_reputation: Dict
    domain_reputation: Dict
    malware_families: List[str]
    threat_types: List[str]
    confidence_score: float
    last_updated: str
    raw_data: Dict

    def __post_init__(self):
        if self.malware_families is None:
            self.malware_families = []
        if self.threat_types is None:
            self.threat_types = []

@dataclass
class ServiceInfo:
    host: str
    port: int
    protocol: str
    service: str
    version: str
    banner: str
    ssl_cert_info: Optional[Dict]
    vulnerability_score: float
    threat_intel: Optional[ThreatIntelData]
    first_seen: str
    last_seen: str

@dataclass
class Alert:
    severity: str
    category: str
    message: str
    host: str
    port: Optional[int]
    timestamp: str
    details: Dict

@dataclass
class PlaybookExecution:
    playbook_name: str
    trigger_alert: Alert
    start_time: str
    status: str
    actions_executed: List[str]
    execution_time: float
    error_message: Optional[str] = None
    ticket_id: Optional[str] = None
    blocked_ips: Optional[List[str]] = None

    def __post_init__(self):
        if self.blocked_ips is None:
            self.blocked_ips = []

class ThreatIntelligence:
    def __init__(self, config: ThreatIntelConfig):
        self.config = config
        self.cache = {}
        self.session = None
        
    async def __aenter__(self):
        # Configuration spéciale pour Windows
        import platform
        if platform.system() == 'Windows':
            import asyncio
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'GUARDIAN/2.0'}
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def get_comprehensive_intel(self, ip: str, domain: Optional[str] = None) -> ThreatIntelData:
        """Collecte des informations de threat intelligence"""
        intel_data = {
            'ip_reputation': {},
            'domain_reputation': {},
            'malware_families': [],
            'threat_types': [],
            'confidence_scores': []
        }

        # Requêtes parallèles pour l'IP
        ip_tasks = []
        if self.config.virustotal_api_key:
            ip_tasks.append(self.query_virustotal_ip(ip))
        if self.config.abuseipdb_api_key:
            ip_tasks.append(self.query_abuseipdb(ip))

        # Exécution des requêtes IP
        if ip_tasks:
            ip_results = await asyncio.gather(*ip_tasks, return_exceptions=True)
            
            for i, result in enumerate(ip_results):
                if isinstance(result, dict) and result:
                    source_name = ['virustotal', 'abuseipdb'][i]
                    intel_data['ip_reputation'][source_name] = result

        # Calcul du score de confiance global
        confidence_score = self._calculate_threat_confidence(intel_data)

        return ThreatIntelData(
            source="comprehensive",
            ip_reputation=intel_data['ip_reputation'],
            domain_reputation=intel_data['domain_reputation'],
            malware_families=list(set(intel_data['malware_families'])),
            threat_types=list(set(intel_data['threat_types'])),
            confidence_score=confidence_score,
            last_updated=datetime.now().isoformat(),
            raw_data=intel_data
        )

    async def query_virustotal_ip(self, ip: str) -> Dict:
        """Interroge VirusTotal pour les informations sur une IP"""
        if not self.config.virustotal_api_key:
            return {}

        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": self.config.virustotal_api_key}
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'malicious': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0),
                        'suspicious': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('suspicious', 0),
                        'harmless': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('harmless', 0),
                        'reputation': data.get('data', {}).get('attributes', {}).get('reputation', 0),
                        'country': data.get('data', {}).get('attributes', {}).get('country', ''),
                        'asn': data.get('data', {}).get('attributes', {}).get('asn', 0),
                        'as_owner': data.get('data', {}).get('attributes', {}).get('as_owner', '')
                    }
                    
        except Exception as e:
            logging.error(f"Erreur VirusTotal IP {ip}: {e}")
            
        return {}

    async def query_abuseipdb(self, ip: str) -> Dict:
        """Interroge AbuseIPDB pour les informations sur une IP"""
        if not self.config.abuseipdb_api_key:
            return {}

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": self.config.abuseipdb_api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'abuse_confidence': data.get('data', {}).get('abuseConfidencePercentage', 0),
                        'is_public': data.get('data', {}).get('isPublic', False),
                        'is_whitelisted': data.get('data', {}).get('isWhitelisted', False),
                        'country_code': data.get('data', {}).get('countryCode', ''),
                        'usage_type': data.get('data', {}).get('usageType', ''),
                        'isp': data.get('data', {}).get('isp', ''),
                        'total_reports': data.get('data', {}).get('totalReports', 0),
                        'last_reported': data.get('data', {}).get('lastReportedAt', '')
                    }
                    
        except Exception as e:
            logging.error(f"Erreur AbuseIPDB {ip}: {e}")
            
        return {}

    def _calculate_threat_confidence(self, intel_data: Dict) -> float:
        """Calcule un score de confiance basé sur les données de threat intelligence"""
        score = 0.0
        factors = 0

        # Score basé sur VirusTotal
        vt_data = intel_data['ip_reputation'].get('virustotal', {})
        if vt_data:
            malicious = vt_data.get('malicious', 0)
            suspicious = vt_data.get('suspicious', 0)
            harmless = vt_data.get('harmless', 0)
            total = malicious + suspicious + harmless
            
            if total > 0:
                threat_ratio = (malicious + suspicious * 0.5) / total
                score += threat_ratio * 0.3
                factors += 1

        # Score basé sur AbuseIPDB
        abuse_data = intel_data['ip_reputation'].get('abuseipdb', {})
        if abuse_data:
            confidence = abuse_data.get('abuse_confidence', 0) / 100
            score += confidence * 0.25
            factors += 1

        # Normalisation
        if factors > 0:
            return min(score / factors if factors > 1 else score, 1.0)
        
        return 0.0

class SiemExporter:
    def __init__(self, config: SiemConfig):
        self.config = config
        self.session = None
        
        # Création du répertoire d'export
        Path(config.export_directory).mkdir(exist_ok=True)
        
        # Mapping des niveaux de sévérité
        self.severity_levels = {
            'LOW': 1,
            'MEDIUM': 2, 
            'HIGH': 3,
            'CRITICAL': 4
        }
        
    async def __aenter__(self):
        if self.config.enabled:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def should_export_alert(self, alert: Alert) -> bool:
        """Détermine si une alerte doit être exportée selon les filtres"""
        min_level = self.severity_levels.get(self.config.min_severity_level, 2)
        alert_level = self.severity_levels.get(alert.severity, 1)
        
        return alert_level >= min_level

    async def export_alerts(self, alerts: List[Alert], services: Optional[Dict[str, ServiceInfo]] = None):
        """Point d'entrée principal pour l'export des alertes"""
        if not self.config.enabled or not alerts:
            return
            
        # Filtrage des alertes
        filtered_alerts = [alert for alert in alerts if self.should_export_alert(alert)]
        
        if not filtered_alerts:
            return
            
        logging.info(f"Export SIEM: {len(filtered_alerts)} alertes vers {self.config.export_format}")
        
        # Export selon le format configuré
        if self.config.export_format == "json":
            await self._export_json(filtered_alerts, services)
        elif self.config.export_format == "cef":
            await self._export_cef(filtered_alerts)
        elif self.config.export_format == "leef":
            await self._export_leef(filtered_alerts)
        elif self.config.export_format == "syslog":
            await self._export_syslog(filtered_alerts)
        elif self.config.export_format == "csv":
            await self._export_csv(filtered_alerts)
        elif self.config.export_format == "xml":
            await self._export_xml(filtered_alerts)
        elif self.config.export_format == "splunk":
            await self._export_splunk(filtered_alerts)
        elif self.config.export_format == "qradar":
            await self._export_qradar(filtered_alerts)
        elif self.config.export_format == "elastic":
            await self._export_elastic(filtered_alerts)

    def _get_export_filename(self, extension: str) -> str:
        """Génère un nom de fichier avec rotation si nécessaire"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{self.config.export_directory}/guardian_alerts_{timestamp}.{extension}"

    async def _export_json(self, alerts: List[Alert], services: Optional[Dict[str, ServiceInfo]] = None):
        """Export au format JSON structuré"""
        export_data = {
            "timestamp": datetime.now().isoformat(),
            "source": "GUARDIAN",
            "version": "2.0",
            "alert_count": len(alerts),
            "alerts": []
        }
        
        for alert in alerts:
            alert_data = {
                "id": hashlib.sha256(f"{alert.timestamp}{alert.host}{alert.port}".encode()).hexdigest(),
                "timestamp": alert.timestamp,
                "severity": alert.severity,
                "category": alert.category,
                "message": alert.message,
                "source_ip": alert.host,
                "source_port": alert.port,
                "details": alert.details,
                "event_type": "attack_surface_change"
            }
            export_data["alerts"].append(alert_data)
        
        filename = self._get_export_filename("json")
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logging.info(f"Export JSON: {filename}")

    async def _export_cef(self, alerts: List[Alert]):
        """Export au format CEF (Common Event Format) pour ArcSight, etc."""
        filename = self._get_export_filename("cef")
        
        with open(filename, 'w') as f:
            for alert in alerts:
                cef_line = (
                    f"CEF:0|GUARDIAN|AttackSurface|2.0|{alert.category}|{alert.message}|"
                    f"{self.severity_levels.get(alert.severity, 1)}|"
                    f"src={alert.host} spt={alert.port or 0} "
                    f"cat={alert.category} "
                    f"rt={int(datetime.fromisoformat(alert.timestamp).timestamp() * 1000)} "
                    f"cs1Label=Details cs1={json.dumps(alert.details)} "
                    f"deviceEventCategory=Attack Surface Analysis\n"
                )
                f.write(cef_line)
        
        logging.info(f"Export CEF: {filename}")
    
    async def _export_leef(self, alerts: List[Alert]):
        """Export au format LEEF (Log Event Extended Format) pour IBM QRadar"""
        filename = self._get_export_filename("leef")
        
        with open(filename, 'w') as f:
            for alert in alerts:
                leef_line = (
                    f"LEEF:2.0|GUARDIAN|AttackSurface|2.0|{alert.category}|"
                    f"src={alert.host} spt={alert.port or 0} "
                    f"sev={self.severity_levels.get(alert.severity, 1)} "
                    f"msg={alert.message} "
                    f"cat={alert.category} "
                    f"rt={int(datetime.fromisoformat(alert.timestamp).timestamp() * 1000)} "
                    f"details={json.dumps(alert.details)}\n"
                )
                f.write(leef_line)
        
        logging.info(f"Export LEEF: {filename}")
    
    async def _export_syslog(self, alerts: List[Alert]):
        """Export au format Syslog"""
        filename = self._get_export_filename("syslog")
        
        with open(filename, 'w') as f:
            for alert in alerts:
                priority = self.severity_levels.get(alert.severity, 6)
                syslog_line = (
                    f"<{priority}>GUARDIAN AttackSurface: "
                    f"src={alert.host} spt={alert.port or 0} "
                    f"sev={alert.severity} cat={alert.category} "
                    f"msg=\"{alert.message}\" "
                    f"details={json.dumps(alert.details)}\n"
                )
                f.write(syslog_line)
        
        logging.info(f"Export Syslog: {filename}")
    
    async def _export_csv(self, alerts: List[Alert]):
        """Export au format CSV"""
        filename = self._get_export_filename("csv")
        
        with open(filename, 'w', newline='') as f:
            import csv
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Severity', 'Category', 'Host', 'Port', 'Message', 'Details'])
            
            for alert in alerts:
                writer.writerow([
                    alert.timestamp,
                    alert.severity,
                    alert.category,
                    alert.host,
                    alert.port or '',
                    alert.message,
                    json.dumps(alert.details)
                ])
        
        logging.info(f"Export CSV: {filename}")
    
    async def _export_xml(self, alerts: List[Alert]):
        """Export au format XML"""
        filename = self._get_export_filename("xml")
        
        xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml_content += '<guardian_alerts>\n'
        
        for alert in alerts:
            xml_content += f'  <alert>\n'
            xml_content += f'    <timestamp>{alert.timestamp}</timestamp>\n'
            xml_content += f'    <severity>{alert.severity}</severity>\n'
            xml_content += f'    <category>{alert.category}</category>\n'
            xml_content += f'    <host>{alert.host}</host>\n'
            xml_content += f'    <port>{alert.port or ""}</port>\n'
            xml_content += f'    <message>{alert.message}</message>\n'
            xml_content += f'    <details>{json.dumps(alert.details)}</details>\n'
            xml_content += f'  </alert>\n'
        
        xml_content += '</guardian_alerts>'
        
        with open(filename, 'w') as f:
            f.write(xml_content)
        
        logging.info(f"Export XML: {filename}")
    
    async def _export_splunk(self, alerts: List[Alert]):
        """Export pour Splunk HEC"""
        filename = self._get_export_filename("splunk")
        
        splunk_events = []
        for alert in alerts:
            event = {
                "time": int(datetime.fromisoformat(alert.timestamp).timestamp()),
                "host": alert.host,
                "source": "guardian",
                "sourcetype": "guardian:attack_surface",
                "event": {
                    "severity": alert.severity,
                    "category": alert.category,
                    "message": alert.message,
                    "port": alert.port,
                    "details": alert.details
                }
            }
            splunk_events.append(event)
        
        with open(filename, 'w') as f:
            json.dump(splunk_events, f, indent=2)
        
        logging.info(f"Export Splunk: {filename}")
    
    async def _export_qradar(self, alerts: List[Alert]):
        """Export pour IBM QRadar"""
        filename = self._get_export_filename("qradar")
        
        qradar_events = []
        for alert in alerts:
            event = {
                "qid": 123456,  # QID personnalisé
                "qname": f"GUARDIAN {alert.category}",
                "qlevel": self.severity_levels.get(alert.severity, 1),
                "magnitude": self.severity_levels.get(alert.severity, 1),
                "credibility": 10,
                "relevance": 10,
                "sourceip": alert.host,
                "sourceport": alert.port or 0,
                "username": "guardian",
                "starttime": int(datetime.fromisoformat(alert.timestamp).timestamp() * 1000),
                "endtime": int(datetime.fromisoformat(alert.timestamp).timestamp() * 1000),
                "protocolid": 0,
                "applicationid": 0,
                "details": alert.details
            }
            qradar_events.append(event)
        
        with open(filename, 'w') as f:
            json.dump(qradar_events, f, indent=2)
        
        logging.info(f"Export QRadar: {filename}")
    
    async def _export_elastic(self, alerts: List[Alert]):
        """Export pour Elasticsearch"""
        filename = self._get_export_filename("elastic")
        
        elastic_events = []
        for alert in alerts:
            event = {
                "@timestamp": alert.timestamp,
                "source": {
                    "ip": alert.host,
                    "port": alert.port
                },
                "guardian": {
                    "severity": alert.severity,
                    "category": alert.category,
                    "message": alert.message,
                    "details": alert.details
                },
                "event": {
                    "category": "attack_surface",
                    "type": alert.category,
                    "severity": alert.severity
                }
            }
            elastic_events.append(event)
        
        with open(filename, 'w') as f:
            json.dump(elastic_events, f, indent=2)
        
        logging.info(f"Export Elasticsearch: {filename}")

class SoarOrchestrator:
    def __init__(self, config: SoarConfig):
        self.config = config
        self.session = None
        self.executions: List[PlaybookExecution] = []
        
    async def __aenter__(self):
        if self.config.enabled:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=300)
            )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def process_alerts(self, alerts: List[Alert], services: Optional[Dict[str, ServiceInfo]] = None):
        """Point d'entrée principal pour traiter les alertes"""
        if not self.config.enabled or not alerts:
            return
            
        logging.info(f"SOAR: Traitement de {len(alerts)} alertes")
        
        # Traitement des alertes critiques
        critical_alerts = [a for a in alerts if a.severity == "CRITICAL"]
        for alert in critical_alerts:
            await self._execute_critical_playbook(alert, services)

    async def _execute_critical_playbook(self, alert: Alert, services: Optional[Dict[str, ServiceInfo]]):
        """Playbook pour alertes critiques"""
        execution = PlaybookExecution(
            playbook_name="Critical_Alert_Response",
            trigger_alert=alert,
            start_time=datetime.now().isoformat(),
            status="RUNNING",
            actions_executed=[],
            execution_time=0.0
        )
        
        start_time = datetime.now()
        
        try:
            logging.warning(f"🚨 PLAYBOOK CRITIQUE: {alert.host}:{alert.port}")
            
            # 1. Notification immédiate
            await self._send_critical_notification(alert)
            execution.actions_executed.append("critical_notification")
            
            # 2. Création de ticket si configuré
            if self.config.auto_create_tickets:
                ticket_id = await self._create_incident_ticket(alert)
                execution.ticket_id = ticket_id
                execution.actions_executed.append("ticket_creation")
            
            execution.status = "SUCCESS"
            logging.info(f"✅ Playbook critique exécuté avec succès")
            
        except Exception as e:
            execution.status = "FAILED"
            execution.error_message = str(e)
            logging.error(f"❌ Échec playbook critique: {e}")
        
        finally:
            execution.execution_time = (datetime.now() - start_time).total_seconds()
            self.executions.append(execution)

    async def _send_critical_notification(self, alert: Alert):
        """Notification critique immédiate"""
        try:
            message = f"🚨 ALERTE CRITIQUE GUARDIAN\n"
            message += f"Host: {alert.host}:{alert.port}\n"
            message += f"Message: {alert.message}\n"
            message += f"🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            
            # Envoi vers Slack
            if self.config.slack_webhook:
                await self._send_slack_message(message, urgent=True)
                
        except Exception as e:
            logging.error(f"Erreur notification critique: {e}")

    async def _send_slack_message(self, message: str, urgent: bool = False):
        """Envoi de message Slack"""
        try:
            if not self.config.slack_webhook:
                return
                
            color = "#ff0000" if urgent else "#ffaa00"
            payload = {
                "attachments": [{
                    "color": color,
                    "title": "🛡️ GUARDIAN Alert" if not urgent else "🚨 GUARDIAN CRITICAL",
                    "text": message,
                    "footer": "GUARDIAN SOAR",
                    "ts": int(datetime.now().timestamp())
                }]
            }
            
            async with self.session.post(self.config.slack_webhook, json=payload) as response:
                if response.status == 200:
                    logging.info("Message Slack envoyé")
                    # Métriques Prometheus
                    try:
                        from prometheus_server import metrics
                        metrics.record_notification("slack")
                    except:
                        pass
                else:
                    logging.error(f"Erreur Slack: {response.status}")
                    
        except Exception as e:
            logging.error(f"Erreur envoi Slack: {e}")
    
    async def _send_teams_message(self, message: str, urgent: bool = False):
        """Envoie un message Microsoft Teams"""
        try:
            if not self.config.teams_webhook:
                return
                
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "0076D7",
                "summary": "GUARDIAN Alert",
                "sections": [{
                    "activityTitle": "🛡️ GUARDIAN Security Alert",
                    "activitySubtitle": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "text": message,
                    "markdown": True
                }]
            }
            
            if urgent:
                payload["themeColor"] = "FF0000"
                payload["sections"][0]["activityTitle"] = "🚨 GUARDIAN CRITICAL ALERT"
            
            async with self.session.post(self.config.teams_webhook, json=payload) as response:
                if response.status == 200:
                    logging.info("Message Teams envoyé")
                    # Métriques Prometheus
                    try:
                        from prometheus_server import metrics
                        metrics.record_notification("teams")
                    except:
                        pass
                else:
                    logging.error(f"Erreur Teams: {response.status}")
                    
        except Exception as e:
            logging.error(f"Erreur envoi Teams: {e}")

    async def _create_incident_ticket(self, alert: Alert) -> Optional[str]:
        """Création de ticket d'incident"""
        try:
            # Simulation de création de ticket
            ticket_id = f"INC{datetime.now().strftime('%Y%m%d%H%M%S')}"
            logging.critical(f"Ticket d'incident créé: {ticket_id}")
            return ticket_id
            
        except Exception as e:
            logging.error(f"Erreur création ticket: {e}")
        
        return None

    def get_execution_summary(self) -> Dict:
        """Résumé des exécutions de playbooks"""
        if not self.executions:
            return {"total": 0, "by_status": {}, "by_playbook": {}}
        
        summary = {
            "total": len(self.executions),
            "by_status": {},
            "by_playbook": {},
            "average_execution_time": sum(e.execution_time for e in self.executions) / len(self.executions),
            "success_rate": len([e for e in self.executions if e.status == "SUCCESS"]) / len(self.executions) * 100
        }
        
        for execution in self.executions:
            # Stats par statut
            status = execution.status
            summary["by_status"][status] = summary["by_status"].get(status, 0) + 1
            
            # Stats par playbook
            playbook = execution.playbook_name
            summary["by_playbook"][playbook] = summary["by_playbook"].get(playbook, 0) + 1
        
        return summary

class AttackSurfaceAnalyzer:
    def __init__(self, config: Config):
        self.config = config
        self.baseline: Dict[str, ServiceInfo] = {}
        self.current_state: Dict[str, ServiceInfo] = {}
        self.alerts: List[Alert] = []
        self.running = False
        
        # Configuration logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(config.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialisation Nmap
        self.nm = nmap.PortScanner()
        
        # Chargement de la baseline existante
        self.load_baseline()

    def load_baseline(self):
        """Charge la baseline depuis le fichier"""
        try:
            if Path(self.config.baseline_file).exists():
                with open(self.config.baseline_file, 'r') as f:
                    data = json.load(f)
                    self.baseline = {}
                    for k, v in data.items():
                        # Reconstruction des objets ThreatIntelData si présent
                        threat_intel = None
                        if v.get('threat_intel') and v['threat_intel'] is not None:
                            try:
                                threat_intel = ThreatIntelData(**v['threat_intel'])
                            except:
                                threat_intel = None
                        
                        service_info = ServiceInfo(
                            host=v['host'],
                            port=v['port'],
                            protocol=v['protocol'],
                            service=v['service'],
                            version=v['version'],
                            banner=v['banner'],
                            ssl_cert_info=v.get('ssl_cert_info'),
                            vulnerability_score=v['vulnerability_score'],
                            threat_intel=threat_intel,
                            first_seen=v['first_seen'],
                            last_seen=v['last_seen']
                        )
                        self.baseline[k] = service_info
                        
                self.logger.info(f"Baseline chargée: {len(self.baseline)} services")
        except Exception as e:
            self.logger.error(f"Erreur chargement baseline: {e}")

    def save_baseline(self):
        """Sauvegarde la baseline actuelle"""
        try:
            data = {}
            for k, v in self.current_state.items():
                service_dict = asdict(v)
                if service_dict.get('threat_intel') and service_dict['threat_intel'] is not None:
                    try:
                        service_dict['threat_intel'] = asdict(service_dict['threat_intel'])
                    except:
                        service_dict['threat_intel'] = None
                data[k] = service_dict
                
            with open(self.config.baseline_file, 'w') as f:
                json.dump(data, f, indent=2)
            self.logger.info("Baseline sauvegardée")
        except Exception as e:
            self.logger.error(f"Erreur sauvegarde baseline: {e}")

    async def scan_network(self, network: str) -> Dict[str, ServiceInfo]:
        """Scan asynchrone d'un réseau avec threat intelligence"""
        services = {}
        
        try:
            self.logger.info(f"Scan en cours: {network}")
            
            # Initialisation de l'interface threat intelligence
            async with ThreatIntelligence(self.config.threat_intel) as threat_intel:
                
                # Scan Nmap avec détection de version et scripts
                nm_args = f"-sV -sC --script ssl-cert -T4"
                
                loop = asyncio.get_event_loop()
                with ThreadPoolExecutor() as executor:
                    scan_result = await loop.run_in_executor(
                        executor, 
                        lambda: self.nm.scan(network, arguments=nm_args)
                    )
                
                for host in self.nm.all_hosts():
                    for protocol in self.nm[host].all_protocols():
                        ports = self.nm[host][protocol].keys()
                        
                        for port in ports:
                            port_info = self.nm[host][protocol][port]
                            
                            if port_info['state'] == 'open':
                                service_key = f"{host}:{port}"
                                
                                # Extraction des informations SSL si disponible
                                ssl_info = await self.get_ssl_info(host, port)
                                
                                # Collecte des informations de threat intelligence
                                threat_data = await threat_intel.get_comprehensive_intel(host)
                                
                                # Calcul du score de vulnérabilité (incluant threat intel)
                                vuln_score = self.calculate_vulnerability_score(
                                    port_info, host, port, threat_data
                                )
                                
                                service = ServiceInfo(
                                    host=host,
                                    port=port,
                                    protocol=protocol,
                                    service=port_info.get('name', 'unknown'),
                                    version=port_info.get('version', ''),
                                    banner=port_info.get('extrainfo', ''),
                                    ssl_cert_info=ssl_info,
                                    vulnerability_score=vuln_score,
                                    threat_intel=threat_data,
                                    first_seen=datetime.now().isoformat(),
                                    last_seen=datetime.now().isoformat()
                                )
                                
                                services[service_key] = service
                                
                                # Log des menaces détectées
                                if threat_data.confidence_score > 0.5:
                                    self.logger.warning(
                                        f"Menace détectée sur {host}:{port} - "
                                        f"Score: {threat_data.confidence_score:.2f}, "
                                        f"Familles: {threat_data.malware_families}"
                                    )
                                
        except Exception as e:
            self.logger.error(f"Erreur scan réseau {network}: {e}")
            
        return services

    async def get_ssl_info(self, host: str, port: int) -> Optional[Dict]:
        """Récupère les informations SSL/TLS d'un service"""
        try:
            if port in [443, 8443, 993, 995, 636]:  # Ports SSL communs
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert_der = ssock.getpeercert(binary_form=True)
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        
                        return {
                            'subject': cert.subject.rfc4514_string(),
                            'issuer': cert.issuer.rfc4514_string(),
                            'not_valid_before': cert.not_valid_before.isoformat(),
                            'not_valid_after': cert.not_valid_after.isoformat(),
                            'serial_number': str(cert.serial_number),
                            'version': cert.version.name,
                            'signature_algorithm': cert.signature_algorithm_oid._name,
                            'days_to_expiry': (cert.not_valid_after - datetime.now()).days
                        }
        except Exception as e:
            self.logger.debug(f"Impossible de récupérer les infos SSL pour {host}:{port} - {e}")
            
        return None

    def calculate_vulnerability_score(self, port_info: Dict, host: str, port: int, threat_data: Optional[ThreatIntelData] = None) -> float:
        """Calcule un score de vulnérabilité basé sur plusieurs facteurs incluant threat intelligence"""
        score = 0.0
        
        # Score basé sur le port (ports dangereux = score plus élevé)
        dangerous_ports = {
            21: 0.7,    # FTP
            22: 0.3,    # SSH
            23: 0.9,    # Telnet
            25: 0.5,    # SMTP
            53: 0.4,    # DNS
            80: 0.6,    # HTTP
            135: 0.8,   # RPC
            139: 0.8,   # NetBIOS
            443: 0.4,   # HTTPS
            445: 0.9,   # SMB
            1433: 0.8,  # MSSQL
            3306: 0.8,  # MySQL
            3389: 0.7,  # RDP
            5432: 0.8,  # PostgreSQL
        }
        
        score += dangerous_ports.get(port, 0.2)
        
        # Score basé sur la version (anciennes versions = score plus élevé)
        version = port_info.get('version', '').lower()
        if any(old in version for old in ['2.0', '1.0', 'old', 'legacy']):
            score += 0.3
            
        # Score basé sur les scripts Nmap (vulnérabilités détectées)
        if 'script' in port_info:
            vuln_keywords = ['vuln', 'cve', 'exploit', 'weak', 'insecure']
            script_output = str(port_info['script']).lower()
            for keyword in vuln_keywords:
                if keyword in script_output:
                    score += 0.2
        
        # Score basé sur threat intelligence
        if threat_data:
            # Ajout du score de confiance threat intel
            threat_score = threat_data.confidence_score
            score += threat_score * 0.4  # Pondération forte pour threat intel
            
            # Bonus pour les familles de malware connues
            if threat_data.malware_families:
                score += min(len(threat_data.malware_families) * 0.1, 0.3)
                
        return min(score, 1.0)  # Cap à 1.0

    def compare_states(self) -> List[Alert]:
        """Compare l'état actuel avec la baseline et génère des alertes"""
        alerts = []
        
        # Services nouveaux
        new_services = set(self.current_state.keys()) - set(self.baseline.keys())
        for service_key in new_services:
            service = self.current_state[service_key]
            
            severity = "HIGH" if service.vulnerability_score > 0.7 else "MEDIUM"
            if service.port in [23, 445, 135]:  # Ports très dangereux
                severity = "CRITICAL"
            
            # Ajustement de la sévérité basé sur threat intelligence
            if service.threat_intel and service.threat_intel.confidence_score > 0.7:
                severity = "CRITICAL"
            elif service.threat_intel and service.threat_intel.confidence_score > 0.5:
                severity = "HIGH"
                
            alert_details = {
                'service': service.service,
                'version': service.version,
                'vulnerability_score': service.vulnerability_score,
                'ssl_info': service.ssl_cert_info
            }
            
            # Ajout des détails threat intelligence
            if service.threat_intel:
                alert_details.update({
                    'threat_confidence': service.threat_intel.confidence_score,
                    'malware_families': service.threat_intel.malware_families,
                    'threat_types': service.threat_intel.threat_types,
                    'ip_reputation_sources': list(service.threat_intel.ip_reputation.keys())
                })
                
            alert = Alert(
                severity=severity,
                category="NEW_SERVICE",
                message=f"Nouveau service détecté: {service.service} sur {service.host}:{service.port}",
                host=service.host,
                port=service.port,
                timestamp=datetime.now().isoformat(),
                details=alert_details
            )
            alerts.append(alert)

        # Alertes spécifiques threat intelligence pour les services critiques
        for service in self.current_state.values():
            if service.threat_intel and service.threat_intel.confidence_score > 0.8:
                # Alerte pour IP très malveillante
                alert = Alert(
                    severity="CRITICAL",
                    category="HIGH_THREAT_IP",
                    message=f"IP hautement malveillante détectée: {service.host}:{service.port}",
                    host=service.host,
                    port=service.port,
                    timestamp=datetime.now().isoformat(),
                    details={
                        'threat_confidence': service.threat_intel.confidence_score,
                        'malware_families': service.threat_intel.malware_families,
                        'threat_sources': list(service.threat_intel.ip_reputation.keys()),
                        'service_details': f"{service.service} {service.version}"
                    }
                )
                alerts.append(alert)

        # Vérification des certificats SSL
        for service in self.current_state.values():
            if service.ssl_cert_info:
                days_to_expiry = service.ssl_cert_info.get('days_to_expiry', 365)
                if days_to_expiry <= 30:  # Seuil configurable
                    severity = "CRITICAL" if days_to_expiry <= 7 else "HIGH"
                    alert = Alert(
                        severity=severity,
                        category="SSL_EXPIRY",
                        message=f"Certificat SSL expire dans {days_to_expiry} jours sur {service.host}:{service.port}",
                        host=service.host,
                        port=service.port,
                        timestamp=datetime.now().isoformat(),
                        details={
                            'days_to_expiry': days_to_expiry,
                            'cert_subject': service.ssl_cert_info.get('subject')
                        }
                    )
                    alerts.append(alert)

        return alerts

    async def run_scan_cycle(self):
        """Exécute un cycle complet de scan"""
        start_time = datetime.now()
        self.logger.info("Début du cycle de scan")
        
        # Reset de l'état actuel
        self.current_state = {}
        
        # Scan de tous les réseaux
        tasks = []
        for network in self.config.target_networks:
            task = self.scan_network(network)
            tasks.append(task)
        
        # Exécution parallèle des scans
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Consolidation des résultats
        for result in results:
            if isinstance(result, dict):
                self.current_state.update(result)
            else:
                self.logger.error(f"Erreur dans un scan: {result}")
        
        scan_duration = (datetime.now() - start_time).total_seconds()
        self.logger.info(f"Scan terminé en {scan_duration:.2f}s: {len(self.current_state)} services détectés")
        
        # Comparaison et génération d'alertes
        if self.baseline:
            alerts = self.compare_states()
            if alerts:
                self.logger.warning(f"{len(alerts)} alertes générées")
                self.alerts.extend(alerts)
                
                # Export SIEM
                if self.config.siem.enabled:
                    async with SiemExporter(self.config.siem) as siem_exporter:
                        await siem_exporter.export_alerts(alerts, self.current_state)
                
                # Exécution des playbooks SOAR
                if self.config.soar.enabled:
                    async with SoarOrchestrator(self.config.soar) as soar_orchestrator:
                        await soar_orchestrator.process_alerts(alerts, self.current_state)
                        
                        # Log du résumé d'exécution
                        summary = soar_orchestrator.get_execution_summary()
                        if summary['total'] > 0:
                            self.logger.info(f"SOAR: {summary['total']} playbooks exécutés, "
                                           f"taux de succès: {summary['success_rate']:.1f}%")
        else:
            self.logger.info("Première exécution - création de la baseline")
        
        # Mise à jour de la baseline
        self.baseline = self.current_state.copy()
        self.save_baseline()

    async def start_monitoring(self):
        """Démarre la surveillance continue"""
        self.running = True
        self.logger.info("Démarrage de la surveillance continue")
        
        while self.running:
            try:
                await self.run_scan_cycle()
                
                # Attente avant le prochain cycle
                await asyncio.sleep(self.config.scan_interval)
                
            except KeyboardInterrupt:
                self.logger.info("Arrêt demandé par l'utilisateur")
                break
            except Exception as e:
                self.logger.error(f"Erreur dans le cycle de surveillance: {e}")
                await asyncio.sleep(60)  # Attente avant retry

    def stop_monitoring(self):
        """Arrête la surveillance"""
        self.running = False
        self.logger.info("Arrêt de la surveillance")

    def generate_report(self) -> str:
        """Génère un rapport de l'état actuel"""
        report = f"""
RAPPORT GUARDIAN - Analyse de Surface d'Attaque
===============================================
Généré le: {datetime.now().isoformat()}

RÉSUMÉ:
- Services actifs: {len(self.current_state)}
- Alertes récentes: {len([a for a in self.alerts if datetime.fromisoformat(a.timestamp) > datetime.now().replace(hour=0, minute=0, second=0)])}

SERVICES PAR CRITICITÉ:
"""
        
        # Regroupement par niveau de criticité
        critical_services = [s for s in self.current_state.values() if s.vulnerability_score > 0.7]
        high_services = [s for s in self.current_state.values() if 0.5 < s.vulnerability_score <= 0.7]
        medium_services = [s for s in self.current_state.values() if 0.3 < s.vulnerability_score <= 0.5]
        low_services = [s for s in self.current_state.values() if s.vulnerability_score <= 0.3]
        
        report += f"- Critiques: {len(critical_services)}\n"
        report += f"- Importants: {len(high_services)}\n"
        report += f"- Moyens: {len(medium_services)}\n"
        report += f"- Faibles: {len(low_services)}\n\n"
        
        # Détail des services critiques
        if critical_services:
            report += "SERVICES CRITIQUES:\n"
            for service in critical_services:
                threat_info = ""
                if service.threat_intel and service.threat_intel.confidence_score > 0.5:
                    threat_info = f" [THREAT: {service.threat_intel.confidence_score:.2f}]"
                report += f"- {service.host}:{service.port} ({service.service} {service.version}) - Score: {service.vulnerability_score:.2f}{threat_info}\n"
        
        # Statistiques Threat Intelligence
        threat_services = [s for s in self.current_state.values() if s.threat_intel and s.threat_intel.confidence_score > 0.3]
        if threat_services:
            report += f"\nSERVICES AVEC THREAT INTELLIGENCE:\n"
            report += f"- Services avec réputation suspecte: {len(threat_services)}\n"
            
            # Top familles de malware détectées
            all_families = []
            for service in threat_services:
                if service.threat_intel.malware_families:
                    all_families.extend(service.threat_intel.malware_families)
            
            if all_families:
                from collections import Counter
                top_families = Counter(all_families).most_common(5)
                report += "- Top familles de malware:\n"
                for family, count in top_families:
                    report += f"  * {family}: {count} occurrences\n"
        
        return report

# Configuration exemple
def create_sample_config() -> Config:
    return Config(
        target_networks=["192.168.1.0/24", "10.0.0.0/24"],
        critical_ports=[21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5432],
        scan_interval=3600,  # 1 heure
        baseline_file="guardian_baseline.json",
        log_file="guardian.log",
        threat_intel=ThreatIntelConfig(
            virustotal_api_key=None,  # Ajoutez votre clé API
            abuseipdb_api_key=None,   # Ajoutez votre clé API
            shodan_api_key=None,      # Ajoutez votre clé API
            use_malwarebazaar=True,
            use_threatfox=True,
            cache_ttl=24
        ),
        siem=SiemConfig(
            enabled=False,  # Activez selon vos besoins
            export_format="json",
            export_directory="./siem_exports",
            min_severity_level="MEDIUM"
        ),
        dashboard=DashboardConfig(
            enabled=False,  # Activez selon vos besoins
            prometheus_enabled=False,
            prometheus_port=8000
        ),
        soar=SoarConfig(
            enabled=False,  # Activez selon vos besoins
            slack_webhook=None,  # Ajoutez votre webhook Slack
            teams_webhook=None,  # Ajoutez votre webhook Teams
            auto_create_tickets=True,
            auto_notify_teams=True
        )
    )

# Interface en ligne de commande
async def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="GUARDIAN - Graphical User Attack Reconnaissance Defense Intelligence & Analysis Network"
    )
    parser.add_argument("--networks", nargs="+", help="Réseaux à scanner (CIDR)")
    parser.add_argument("--single-scan", action="store_true", help="Exécution unique")
    parser.add_argument("--report", action="store_true", help="Génère uniquement un rapport")
    parser.add_argument("--baseline-reset", action="store_true", help="Recrée la baseline")
    parser.add_argument("--export-format", choices=["json", "cef", "leef", "syslog", "csv", "xml", "splunk", "qradar", "elastic"], help="Format d'export SIEM")
    parser.add_argument("--export-directory", default="./siem_exports", help="Répertoire d'export SIEM")
    parser.add_argument("--prometheus-metrics", action="store_true", help="Active les métriques Prometheus")
    parser.add_argument("--prometheus-port", type=int, default=8000, help="Port pour les métriques Prometheus")
    parser.add_argument("--create-sample-config", action="store_true", help="Crée un fichier de configuration exemple")
    parser.add_argument("--test-siem", action="store_true", help="Test des exports SIEM")
    parser.add_argument("--test-soar", action="store_true", help="Test des playbooks SOAR")
    parser.add_argument("--slack-webhook", help="Webhook Slack pour notifications")
    parser.add_argument("--teams-webhook", help="Webhook Teams pour notifications")
    parser.add_argument("--servicenow-url", help="URL ServiceNow pour tickets")
    parser.add_argument("--servicenow-username", help="Nom d'utilisateur ServiceNow")
    parser.add_argument("--servicenow-password", help="Mot de passe ServiceNow")
    parser.add_argument("--version", action="version", version="GUARDIAN 2.0")
    
    args = parser.parse_args()
    
    print("""
    GUARDIAN
    ========
    
    Graphical User Attack Reconnaissance Defense Intelligence & Analysis Network
    Version 2.0 - Analyseur de Surface d'Attaque
    """)
    
    # Gestion des arguments spéciaux
    if args.create_sample_config:
        config = create_sample_config()
        with open("guardian_config_sample.json", "w") as f:
            json.dump(config.__dict__, f, indent=2, default=str)
        print("✅ Configuration exemple créée: guardian_config_sample.json")
        return
    
    if args.test_siem:
        print("🧪 TEST DES EXPORTS SIEM")
        from guardian import SiemExporter, Alert
        test_config = create_sample_config()
        test_config.siem.enabled = True
        test_config.siem.export_format = "json"
        
        test_alert = Alert(
            severity="HIGH",
            category="test_siem",
            message="Test d'export SIEM",
            host="192.168.1.1",
            port=8080,
            timestamp=datetime.now().isoformat(),
            details={"test": True}
        )
        
        async with SiemExporter(test_config.siem) as siem:
            await siem.export_alerts([test_alert])
        print("✅ Test SIEM terminé")
        return
    
    if args.test_soar:
        print("🧪 TEST DES PLAYBOOKS SOAR")
        from guardian import SoarOrchestrator, Alert
        test_config = create_sample_config()
        test_config.soar.enabled = True
        
        test_alert = Alert(
            severity="CRITICAL",
            category="test_soar",
            message="Test de playbook SOAR",
            host="192.168.1.1",
            port=8080,
            timestamp=datetime.now().isoformat(),
            details={"test": True}
        )
        
        async with SoarOrchestrator(test_config.soar) as soar:
            await soar.process_alerts([test_alert])
        print("✅ Test SOAR terminé")
        return
    
    # Démarrage du serveur Prometheus si demandé
    if args.prometheus_metrics:
        from prometheus_server import start_prometheus_server
        if start_prometheus_server(args.prometheus_port):
            print(f"📊 Métriques Prometheus disponibles sur http://localhost:{args.prometheus_port}/metrics")
    
    # Configuration
    config = create_sample_config()
    
    # Mise à jour de la configuration avec les arguments
    if args.networks:
        config.target_networks = args.networks
        print(f"🎯 Réseaux configurés: {', '.join(args.networks)}")
    
    if args.export_format:
        config.siem.enabled = True
        config.siem.export_format = args.export_format
        print(f"📤 Export SIEM configuré: {args.export_format}")
    
    if args.export_directory:
        config.siem.export_directory = args.export_directory
        print(f"📁 Répertoire d'export: {args.export_directory}")
    
    if args.slack_webhook:
        config.soar.enabled = True
        config.soar.slack_webhook = args.slack_webhook
        print("💬 Webhook Slack configuré")
    
    if args.teams_webhook:
        config.soar.enabled = True
        config.soar.teams_webhook = args.teams_webhook
        print("💬 Webhook Teams configuré")
    
    if args.servicenow_url:
        config.soar.enabled = True
        # Ajout des credentials ServiceNow à la config
        print("🎫 ServiceNow configuré")
    
    if not args.networks and not args.create_sample_config and not args.test_siem and not args.test_soar:
        print("⚠️  Utilisation de la configuration par défaut")
    
    # Initialisation de l'analyseur
    try:
        analyzer = AttackSurfaceAnalyzer(config)
    except Exception as e:
        print(f"❌ Erreur initialisation: {e}")
        return
    
    try:
        if args.baseline_reset:
            analyzer.baseline = {}
            analyzer.save_baseline()
            print("✅ Baseline réinitialisée")
            return
            
        if args.report:
            report = analyzer.generate_report()
            print(report)
            return
            
        if args.single_scan:
            print("🔍 Lancement d'un scan unique...")
            print(f"🎯 Réseaux: {', '.join(config.target_networks)}")
            
            await analyzer.run_scan_cycle()
            report = analyzer.generate_report()
            print(report)
            
            if analyzer.alerts:
                print(f"\n🚨 {len(analyzer.alerts)} alertes générées:")
                for alert in analyzer.alerts:
                    print(f"   [{alert.severity}] {alert.message}")
        else:
            # Surveillance continue
            print(f"🚀 Démarrage de la surveillance continue...")
            print(f"📡 Réseaux surveillés: {', '.join(config.target_networks)}")
            print(f"⏰ Intervalle: {config.scan_interval}s ({config.scan_interval/60:.1f} min)")
            
            print("\n⚡ GUARDIAN est opérationnel ! Appuyez sur Ctrl+C pour arrêter.\n")
            
            await analyzer.start_monitoring()
            
    except KeyboardInterrupt:
        analyzer.stop_monitoring()
        print("\n🛑 GUARDIAN arrêté proprement")
    except Exception as e:
        print(f"❌ Erreur: {e}")
        logging.error(f"Erreur critique: {e}")

if __name__ == "__main__":
    # Configuration spéciale pour Windows
    import platform
    if platform.system() == 'Windows':
        import asyncio
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    # Vérification des permissions (Nmap nécessite souvent des privilèges)
    try:
        import os
        if os.name != 'nt' and os.geteuid() != 0:  # Unix et pas root
            print("⚠️  Attention: GUARDIAN fonctionne mieux avec des privilèges administrateur")
            print("💡 Considérez l'utilisation de: sudo python guardian.py")
    except:
        pass
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Au revoir !")
    except Exception as e:
        print(f"Erreur fatale: {e}")
        exit(1) 