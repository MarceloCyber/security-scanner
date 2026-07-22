from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, JSON, Float
from datetime import datetime
from database import Base

class MonitorTarget(Base):
    """Alvos de monitoramento (redes, sistemas, servidores)"""
    __tablename__ = "monitor_targets"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    name = Column(String, nullable=False)  # Nome do alvo
    target_type = Column(String, nullable=False)  # network, server, application, api
    target_address = Column(String, nullable=False)  # IP, URL, domínio
    monitoring_ports = Column(JSON, nullable=True)  # Portas a monitorar
    status = Column(String, default="active")  # active, paused, inactive
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Configurações de monitoramento
    check_interval = Column(Integer, default=300)  # Intervalo em segundos (padrão 5min)
    alert_threshold = Column(Integer, default=3)  # Número de falhas antes de alertar
    enable_email_alerts = Column(Boolean, default=True)
    enable_telegram_alerts = Column(Boolean, default=False)
    telegram_chat_id = Column(String, nullable=True)
    
    # Métricas
    last_check = Column(DateTime, nullable=True)
    uptime_percentage = Column(Float, default=100.0)
    total_checks = Column(Integer, default=0)
    failed_checks = Column(Integer, default=0)

class MonitorIncident(Base):
    """Incidentes detectados pelo monitoramento"""
    __tablename__ = "monitor_incidents"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, index=True)
    user_id = Column(Integer, index=True)
    
    # Informações do incidente
    incident_type = Column(String, nullable=False)  # port_scan, brute_force, ddos, unauthorized_access, anomaly
    severity = Column(String, nullable=False)  # low, medium, high, critical
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    detected_at = Column(DateTime, default=datetime.utcnow)
    
    # Detalhes técnicos
    source_ip = Column(String, nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    request_count = Column(Integer, nullable=True)
    payload = Column(Text, nullable=True)
    
    # Status
    status = Column(String, default="open")  # open, investigating, resolved, false_positive
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String, nullable=True)
    notes = Column(Text, nullable=True)
    
    # Ações tomadas
    auto_blocked = Column(Boolean, default=False)
    blocked_ip = Column(String, nullable=True)
    
    # Metadados adicionais
    extra_data = Column(JSON, nullable=True)

class MonitorLog(Base):
    """Logs de atividade do monitoramento"""
    __tablename__ = "monitor_logs"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, index=True)
    user_id = Column(Integer, index=True)
    
    log_type = Column(String, nullable=False)  # check, alert, block, error
    message = Column(Text, nullable=False)
    level = Column(String, default="info")  # debug, info, warning, error, critical
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Dados adicionais
    data = Column(JSON, nullable=True)

class BlockedIP(Base):
    """IPs bloqueados automaticamente"""
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, index=True)
    user_id = Column(Integer, index=True)
    
    ip_address = Column(String, nullable=False, index=True)
    reason = Column(String, nullable=False)
    blocked_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    
    is_permanent = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    
    # Informações adicionais
    country = Column(String, nullable=True)
    asn = Column(String, nullable=True)
    threat_score = Column(Integer, nullable=True)
    notes = Column(Text, nullable=True)
