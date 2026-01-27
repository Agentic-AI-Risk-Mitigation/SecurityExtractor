#!/usr/bin/env python3
"""
IaC Security Threat Model
=========================

Defines the security patterns and threat categories for Infrastructure-as-Code.
This threat model is specifically designed for Stream 2 research:
detecting security posture changes in Terraform, Kubernetes, Docker, and Ansible.

The model follows CWE (Common Weakness Enumeration) and maps to:
- OWASP Top 10 for Infrastructure
- CIS Benchmarks
- Cloud provider security best practices
"""

import re
import json
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum


# =============================================================================
# THREAT CATEGORIES (based on STRIDE + IaC-specific)
# =============================================================================

class ThreatCategory(Enum):
    """Categories of threats in IaC configurations"""
    
    # STRIDE-based
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    TAMPERING = "tampering"
    SPOOFING = "spoofing"
    
    # IaC-specific
    INSECURE_DEFAULTS = "insecure_defaults"
    MISSING_ENCRYPTION = "missing_encryption"
    OVERLY_PERMISSIVE = "overly_permissive"
    HARDCODED_SECRETS = "hardcoded_secrets"
    MISSING_LOGGING = "missing_logging"
    INSECURE_NETWORK = "insecure_network"
    WEAK_AUTHENTICATION = "weak_authentication"


class Severity(Enum):
    """Severity levels for vulnerabilities"""
    CRITICAL = 4  # Immediate exploitation possible, high impact
    HIGH = 3      # Serious security issue
    MEDIUM = 2    # Moderate risk
    LOW = 1       # Minor issue
    INFO = 0      # Informational


class PostureDirection(Enum):
    """Direction of security posture change"""
    RESTRICTIVE_TO_PERMISSIVE = "regression"    # Security weakened
    PERMISSIVE_TO_RESTRICTIVE = "improvement"   # Security strengthened
    NEUTRAL = "neutral"                         # No significant change


# =============================================================================
# PATTERN DEFINITIONS
# =============================================================================

@dataclass
class SecurityPattern:
    """
    Defines a single security pattern to detect.
    
    A pattern can be either:
    - PERMISSIVE: Indicates a potentially insecure configuration
    - RESTRICTIVE: Indicates a secure configuration
    
    By tracking both, we can detect posture CHANGES.
    """
    id: str                          # Unique identifier (e.g., "K8S-001")
    name: str                        # Human-readable name
    description: str                 # What this pattern detects
    regex: str                       # Regular expression to match
    is_permissive: bool              # True = insecure, False = secure
    severity: Severity               # How severe is this if permissive
    category: ThreatCategory         # Type of threat
    cwe_id: Optional[str] = None     # CWE reference if applicable
    remediation: str = ""            # How to fix
    file_types: list = field(default_factory=lambda: ['all'])  # Which IaC types
    
    def matches(self, content: str) -> list[dict]:
        """Find all matches of this pattern in content"""
        matches = []
        lines = content.split('\n')
        
        try:
            for i, line in enumerate(lines, 1):
                if re.search(self.regex, line, re.IGNORECASE):
                    matches.append({
                        'line_number': i,
                        'line_content': line.strip()[:100],
                        'pattern_id': self.id,
                        'pattern_name': self.name,
                        'is_permissive': self.is_permissive,
                        'severity': self.severity.name,
                    })
        except re.error:
            pass  # Invalid regex, skip
        
        return matches


# =============================================================================
# KUBERNETES THREAT MODEL
# =============================================================================

KUBERNETES_PATTERNS = [
    # Container Security Context
    SecurityPattern(
        id="K8S-001",
        name="Privileged Container",
        description="Container running with privileged flag enables full host access",
        regex=r'privileged:\s*true',
        is_permissive=True,
        severity=Severity.CRITICAL,
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        cwe_id="CWE-250",
        remediation="Set privileged: false and use specific capabilities if needed",
        file_types=['kubernetes'],
    ),
    SecurityPattern(
        id="K8S-002",
        name="Non-Privileged Container",
        description="Container running without privileged flag (secure)",
        regex=r'privileged:\s*false',
        is_permissive=False,
        severity=Severity.INFO,
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        file_types=['kubernetes'],
    ),
    SecurityPattern(
        id="K8S-003",
        name="Running as Root",
        description="Container running as root user (UID 0)",
        regex=r'runAsUser:\s*0\b',
        is_permissive=True,
        severity=Severity.HIGH,
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        cwe_id="CWE-250",
        remediation="Use runAsUser with non-zero UID and runAsNonRoot: true",
        file_types=['kubernetes'],
    ),
    SecurityPattern(
        id="K8S-004",
        name="Must Run as Non-Root",
        description="Container must run as non-root user (secure)",
        regex=r'runAsNonRoot:\s*true',
        is_permissive=False,
        severity=Severity.INFO,
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        file_types=['kubernetes'],
    ),
    SecurityPattern(
        id="K8S-005",
        name="Privilege Escalation Allowed",
        description="Container can escalate privileges",
        regex=r'allowPrivilegeEscalation:\s*true',
        is_permissive=True,
        severity=Severity.HIGH,
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        cwe_id="CWE-269",
        remediation="Set allowPrivilegeEscalation: false",
        file_types=['kubernetes'],
    ),
    SecurityPattern(
        id="K8S-006",
        name="Privilege Escalation Blocked",
        description="Container cannot escalate privileges (secure)",
        regex=r'allowPrivilegeEscalation:\s*false',
        is_permissive=False,
        severity=Severity.INFO,
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        file_types=['kubernetes'],
    ),
    
    # Filesystem Security
    SecurityPattern(
        id="K8S-010",
        name="Writable Root Filesystem",
        description="Container has writable root filesystem",
        regex=r'readOnlyRootFilesystem:\s*false',
        is_permissive=True,
        severity=Severity.MEDIUM,
        category=ThreatCategory.TAMPERING,
        remediation="Set readOnlyRootFilesystem: true and use volumes for writable data",
        file_types=['kubernetes'],
    ),
    SecurityPattern(
        id="K8S-011",
        name="Read-Only Root Filesystem",
        description="Container has read-only root filesystem (secure)",
        regex=r'readOnlyRootFilesystem:\s*true',
        is_permissive=False,
        severity=Severity.INFO,
        category=ThreatCategory.TAMPERING,
        file_types=['kubernetes'],
    ),
    
    # Host Access
    SecurityPattern(
        id="K8S-020",
        name="Host Network Access",
        description="Pod has access to host network namespace",
        regex=r'hostNetwork:\s*true',
        is_permissive=True,
        severity=Severity.HIGH,
        category=ThreatCategory.INSECURE_NETWORK,
        cwe_id="CWE-668",
        remediation="Set hostNetwork: false unless absolutely necessary",
        file_types=['kubernetes'],
    ),
    SecurityPattern(
        id="K8S-021",
        name="Host PID Access",
        description="Pod has access to host PID namespace",
        regex=r'hostPID:\s*true',
        is_permissive=True,
        severity=Severity.HIGH,
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        remediation="Set hostPID: false",
        file_types=['kubernetes'],
    ),
    SecurityPattern(
        id="K8S-022",
        name="Host IPC Access",
        description="Pod has access to host IPC namespace",
        regex=r'hostIPC:\s*true',
        is_permissive=True,
        severity=Severity.MEDIUM,
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        remediation="Set hostIPC: false",
        file_types=['kubernetes'],
    ),
    
    # Capabilities
    SecurityPattern(
        id="K8S-030",
        name="Dangerous Capabilities Added",
        description="Container adds dangerous capabilities like SYS_ADMIN or ALL",
        regex=r'add:\s*\n\s*-\s*(ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE)',
        is_permissive=True,
        severity=Severity.CRITICAL,
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        cwe_id="CWE-250",
        remediation="Drop all capabilities and add only what's needed",
        file_types=['kubernetes'],
    ),
    SecurityPattern(
        id="K8S-031",
        name="All Capabilities Dropped",
        description="Container drops all capabilities (secure)",
        regex=r'drop:\s*\n\s*-\s*ALL',
        is_permissive=False,
        severity=Severity.INFO,
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        file_types=['kubernetes'],
    ),
    
    # Service Account
    SecurityPattern(
        id="K8S-040",
        name="Auto-Mount Service Account Token",
        description="Service account token automatically mounted in pod",
        regex=r'automountServiceAccountToken:\s*true',
        is_permissive=True,
        severity=Severity.MEDIUM,
        category=ThreatCategory.INFORMATION_DISCLOSURE,
        remediation="Set automountServiceAccountToken: false if not needed",
        file_types=['kubernetes'],
    ),
    
    # Secrets
    SecurityPattern(
        id="K8S-050",
        name="Hardcoded Secret in Env",
        description="Secret value hardcoded in environment variable",
        regex=r'value:\s*["\'][A-Za-z0-9+/=]{20,}["\']',
        is_permissive=True,
        severity=Severity.CRITICAL,
        category=ThreatCategory.HARDCODED_SECRETS,
        cwe_id="CWE-798",
        remediation="Use Kubernetes Secrets or external secret management",
        file_types=['kubernetes'],
    ),
]


# =============================================================================
# TERRAFORM THREAT MODEL
# =============================================================================

TERRAFORM_PATTERNS = [
    # Public Access
    SecurityPattern(
        id="TF-001",
        name="Publicly Accessible Resource",
        description="Resource is publicly accessible from internet",
        regex=r'publicly_accessible\s*=\s*true',
        is_permissive=True,
        severity=Severity.HIGH,
        category=ThreatCategory.INSECURE_NETWORK,
        cwe_id="CWE-284",
        remediation="Set publicly_accessible = false",
        file_types=['terraform'],
    ),
    SecurityPattern(
        id="TF-002",
        name="Private Resource",
        description="Resource is not publicly accessible (secure)",
        regex=r'publicly_accessible\s*=\s*false',
        is_permissive=False,
        severity=Severity.INFO,
        category=ThreatCategory.INSECURE_NETWORK,
        file_types=['terraform'],
    ),
    
    # Encryption
    SecurityPattern(
        id="TF-010",
        name="Encryption Disabled",
        description="Encryption is explicitly disabled",
        regex=r'encrypt(ed|ion)?\s*=\s*false',
        is_permissive=True,
        severity=Severity.HIGH,
        category=ThreatCategory.MISSING_ENCRYPTION,
        cwe_id="CWE-311",
        remediation="Enable encryption: encrypted = true",
        file_types=['terraform'],
    ),
    SecurityPattern(
        id="TF-011",
        name="Encryption Enabled",
        description="Encryption is enabled (secure)",
        regex=r'encrypt(ed|ion)?\s*=\s*true',
        is_permissive=False,
        severity=Severity.INFO,
        category=ThreatCategory.MISSING_ENCRYPTION,
        file_types=['terraform'],
    ),
    SecurityPattern(
        id="TF-012",
        name="KMS Key Configured",
        description="KMS key configured for encryption (secure)",
        regex=r'kms_key_id\s*=',
        is_permissive=False,
        severity=Severity.INFO,
        category=ThreatCategory.MISSING_ENCRYPTION,
        file_types=['terraform'],
    ),
    
    # Network Security
    SecurityPattern(
        id="TF-020",
        name="Open CIDR Block",
        description="Security group allows access from 0.0.0.0/0 (entire internet)",
        regex=r'cidr_blocks?\s*=\s*\[?\s*["\']0\.0\.0\.0/0["\']',
        is_permissive=True,
        severity=Severity.CRITICAL,
        category=ThreatCategory.INSECURE_NETWORK,
        cwe_id="CWE-284",
        remediation="Restrict CIDR blocks to specific IP ranges",
        file_types=['terraform'],
    ),
    SecurityPattern(
        id="TF-021",
        name="All Ports Open",
        description="Security group allows all ports (0-65535)",
        regex=r'from_port\s*=\s*0.*to_port\s*=\s*65535',
        is_permissive=True,
        severity=Severity.CRITICAL,
        category=ThreatCategory.INSECURE_NETWORK,
        cwe_id="CWE-284",
        remediation="Specify only the required ports",
        file_types=['terraform'],
    ),
    SecurityPattern(
        id="TF-022",
        name="All Protocols Allowed",
        description="Security group allows all protocols",
        regex=r'protocol\s*=\s*["\'](-1|all)["\']',
        is_permissive=True,
        severity=Severity.HIGH,
        category=ThreatCategory.INSECURE_NETWORK,
        remediation="Specify only required protocols (tcp, udp)",
        file_types=['terraform'],
    ),
    
    # S3 Security
    SecurityPattern(
        id="TF-030",
        name="Public S3 ACL",
        description="S3 bucket has public-read or public-read-write ACL",
        regex=r'acl\s*=\s*["\']public-(read|read-write)["\']',
        is_permissive=True,
        severity=Severity.CRITICAL,
        category=ThreatCategory.OVERLY_PERMISSIVE,
        cwe_id="CWE-284",
        remediation="Use acl = \"private\" and explicit policies",
        file_types=['terraform'],
    ),
    SecurityPattern(
        id="TF-031",
        name="Private S3 ACL",
        description="S3 bucket has private ACL (secure)",
        regex=r'acl\s*=\s*["\']private["\']',
        is_permissive=False,
        severity=Severity.INFO,
        category=ThreatCategory.OVERLY_PERMISSIVE,
        file_types=['terraform'],
    ),
    SecurityPattern(
        id="TF-032",
        name="S3 Versioning Disabled",
        description="S3 bucket versioning is disabled",
        regex=r'versioning\s*\{[^}]*enabled\s*=\s*false',
        is_permissive=True,
        severity=Severity.MEDIUM,
        category=ThreatCategory.TAMPERING,
        remediation="Enable versioning for data protection",
        file_types=['terraform'],
    ),
    
    # Logging & Monitoring
    SecurityPattern(
        id="TF-040",
        name="Logging Disabled",
        description="Logging is disabled for resource",
        regex=r'logging\s*\{[^}]*enabled\s*=\s*false',
        is_permissive=True,
        severity=Severity.MEDIUM,
        category=ThreatCategory.MISSING_LOGGING,
        cwe_id="CWE-778",
        remediation="Enable logging for audit trail",
        file_types=['terraform'],
    ),
    
    # SSL/TLS
    SecurityPattern(
        id="TF-050",
        name="SSL Not Required",
        description="SSL/TLS is not required for connections",
        regex=r'require_ssl\s*=\s*false',
        is_permissive=True,
        severity=Severity.HIGH,
        category=ThreatCategory.MISSING_ENCRYPTION,
        cwe_id="CWE-319",
        remediation="Set require_ssl = true",
        file_types=['terraform'],
    ),
    SecurityPattern(
        id="TF-051",
        name="SSL Required",
        description="SSL/TLS is required (secure)",
        regex=r'require_ssl\s*=\s*true',
        is_permissive=False,
        severity=Severity.INFO,
        category=ThreatCategory.MISSING_ENCRYPTION,
        file_types=['terraform'],
    ),
    
    # Deletion Protection
    SecurityPattern(
        id="TF-060",
        name="Deletion Protection Disabled",
        description="Resource can be accidentally deleted",
        regex=r'deletion_protection\s*=\s*false',
        is_permissive=True,
        severity=Severity.MEDIUM,
        category=ThreatCategory.DENIAL_OF_SERVICE,
        remediation="Set deletion_protection = true for production resources",
        file_types=['terraform'],
    ),
]


# =============================================================================
# DOCKER THREAT MODEL
# =============================================================================

DOCKER_PATTERNS = [
    # User Context
    SecurityPattern(
        id="DOCKER-001",
        name="Running as Root",
        description="Container runs as root user",
        regex=r'USER\s+root',
        is_permissive=True,
        severity=Severity.HIGH,
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        cwe_id="CWE-250",
        remediation="Use USER with a non-root user or numeric UID",
        file_types=['docker'],
    ),
    SecurityPattern(
        id="DOCKER-002",
        name="Non-Root User",
        description="Container runs as non-root user (secure)",
        regex=r'USER\s+([a-z]+|\d+)',
        is_permissive=False,
        severity=Severity.INFO,
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        file_types=['docker'],
    ),
    
    # Build Security
    SecurityPattern(
        id="DOCKER-010",
        name="ADD from URL",
        description="ADD instruction fetches from URL (prefer COPY)",
        regex=r'ADD\s+https?://',
        is_permissive=True,
        severity=Severity.MEDIUM,
        category=ThreatCategory.TAMPERING,
        cwe_id="CWE-494",
        remediation="Use COPY with verified files instead of ADD from URLs",
        file_types=['docker'],
    ),
    SecurityPattern(
        id="DOCKER-011",
        name="Curl Piped to Shell",
        description="Downloading and executing script in one command",
        regex=r'curl\s+.*\|\s*(bash|sh)',
        is_permissive=True,
        severity=Severity.HIGH,
        category=ThreatCategory.TAMPERING,
        cwe_id="CWE-494",
        remediation="Download files first, verify, then execute",
        file_types=['docker'],
    ),
    
    # Permissions
    SecurityPattern(
        id="DOCKER-020",
        name="World-Writable Permissions",
        description="File permissions set to 777 (world-writable)",
        regex=r'chmod\s+777',
        is_permissive=True,
        severity=Severity.HIGH,
        category=ThreatCategory.OVERLY_PERMISSIVE,
        cwe_id="CWE-732",
        remediation="Use minimal required permissions (e.g., 755 or 644)",
        file_types=['docker'],
    ),
    
    # Network
    SecurityPattern(
        id="DOCKER-030",
        name="SSH Port Exposed",
        description="Container exposes SSH port 22",
        regex=r'EXPOSE\s+22',
        is_permissive=True,
        severity=Severity.MEDIUM,
        category=ThreatCategory.INSECURE_NETWORK,
        remediation="Avoid running SSH in containers; use kubectl exec or docker exec",
        file_types=['docker'],
    ),
    
    # Secrets
    SecurityPattern(
        id="DOCKER-040",
        name="Hardcoded Secret in ENV",
        description="Environment variable contains hardcoded secret",
        regex=r'ENV\s+\w*(PASSWORD|SECRET|KEY|TOKEN)\w*\s*=?\s*["\']?[A-Za-z0-9]{8,}',
        is_permissive=True,
        severity=Severity.CRITICAL,
        category=ThreatCategory.HARDCODED_SECRETS,
        cwe_id="CWE-798",
        remediation="Use Docker secrets or environment variables at runtime",
        file_types=['docker'],
    ),
    
    # Health
    SecurityPattern(
        id="DOCKER-050",
        name="Health Check Configured",
        description="Container has health check configured (secure)",
        regex=r'HEALTHCHECK',
        is_permissive=False,
        severity=Severity.INFO,
        category=ThreatCategory.DENIAL_OF_SERVICE,
        file_types=['docker'],
    ),
]


# =============================================================================
# ANSIBLE THREAT MODEL
# =============================================================================

ANSIBLE_PATTERNS = [
    # Privilege Escalation
    SecurityPattern(
        id="ANSIBLE-001",
        name="Becoming Root",
        description="Task escalates to root user",
        regex=r'become:\s*(yes|true).*become_user:\s*root',
        is_permissive=True,
        severity=Severity.MEDIUM,
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        remediation="Use minimal required privileges or specific service accounts",
        file_types=['ansible'],
    ),
    
    # Certificate Validation
    SecurityPattern(
        id="ANSIBLE-010",
        name="Certificate Validation Disabled",
        description="SSL certificate validation is disabled",
        regex=r'validate_certs:\s*(no|false)',
        is_permissive=True,
        severity=Severity.HIGH,
        category=ThreatCategory.SPOOFING,
        cwe_id="CWE-295",
        remediation="Set validate_certs: yes",
        file_types=['ansible'],
    ),
    SecurityPattern(
        id="ANSIBLE-011",
        name="Certificate Validation Enabled",
        description="SSL certificate validation is enabled (secure)",
        regex=r'validate_certs:\s*(yes|true)',
        is_permissive=False,
        severity=Severity.INFO,
        category=ThreatCategory.SPOOFING,
        file_types=['ansible'],
    ),
    
    # Permissions
    SecurityPattern(
        id="ANSIBLE-020",
        name="World-Writable File Mode",
        description="File mode set to 0777 (world-writable)",
        regex=r'mode:\s*["\']?0?777',
        is_permissive=True,
        severity=Severity.HIGH,
        category=ThreatCategory.OVERLY_PERMISSIVE,
        cwe_id="CWE-732",
        remediation="Use minimal required permissions",
        file_types=['ansible'],
    ),
    
    # Secrets
    SecurityPattern(
        id="ANSIBLE-030",
        name="Hardcoded Password",
        description="Password appears to be hardcoded in playbook",
        regex=r'password:\s*["\'][^{$][^"\']{4,}["\']',
        is_permissive=True,
        severity=Severity.CRITICAL,
        category=ThreatCategory.HARDCODED_SECRETS,
        cwe_id="CWE-798",
        remediation="Use Ansible Vault or external secret management",
        file_types=['ansible'],
    ),
    SecurityPattern(
        id="ANSIBLE-031",
        name="SSH Password in Vars",
        description="SSH password stored in variables",
        regex=r'ansible_ssh_pass:',
        is_permissive=True,
        severity=Severity.HIGH,
        category=ThreatCategory.HARDCODED_SECRETS,
        remediation="Use SSH keys instead of passwords",
        file_types=['ansible'],
    ),
    
    # Logging
    SecurityPattern(
        id="ANSIBLE-040",
        name="Sensitive Data Logged",
        description="Task may log sensitive data (no_log: false)",
        regex=r'no_log:\s*(no|false)',
        is_permissive=True,
        severity=Severity.MEDIUM,
        category=ThreatCategory.INFORMATION_DISCLOSURE,
        remediation="Set no_log: true for tasks with sensitive data",
        file_types=['ansible'],
    ),
    SecurityPattern(
        id="ANSIBLE-041",
        name="Sensitive Data Not Logged",
        description="Task suppresses logging of sensitive data (secure)",
        regex=r'no_log:\s*(yes|true)',
        is_permissive=False,
        severity=Severity.INFO,
        category=ThreatCategory.INFORMATION_DISCLOSURE,
        file_types=['ansible'],
    ),
]


# =============================================================================
# THREAT MODEL CLASS
# =============================================================================

class IaCThreatModel:
    """
    Complete threat model for IaC security analysis.
    
    Usage:
        model = IaCThreatModel()
        
        # Analyze a single file
        findings = model.analyze_content(content, 'kubernetes')
        
        # Compare before/after for posture change
        change = model.analyze_posture_change(before, after, 'terraform')
    """
    
    def __init__(self):
        # Combine all patterns
        self.all_patterns = (
            KUBERNETES_PATTERNS +
            TERRAFORM_PATTERNS +
            DOCKER_PATTERNS +
            ANSIBLE_PATTERNS
        )
        
        # Index by file type
        self.patterns_by_type = {
            'kubernetes': [p for p in self.all_patterns if 'kubernetes' in p.file_types],
            'terraform': [p for p in self.all_patterns if 'terraform' in p.file_types],
            'docker': [p for p in self.all_patterns if 'docker' in p.file_types],
            'ansible': [p for p in self.all_patterns if 'ansible' in p.file_types],
        }
        
        # Severity weights for risk calculation
        self.severity_weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 5,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
    
    def detect_file_type(self, filename: str, content: str = '') -> str:
        """Detect IaC file type from filename and content"""
        filename_lower = filename.lower()
        
        if filename_lower.endswith('.tf') or filename_lower.endswith('.tfvars'):
            return 'terraform'
        if 'dockerfile' in filename_lower:
            return 'docker'
        if filename_lower.endswith(('.yaml', '.yml')):
            if any(k in content.lower() for k in ['apiversion:', 'kind:']):
                return 'kubernetes'
            if any(k in content.lower() for k in ['hosts:', 'tasks:']):
                return 'ansible'
            return 'kubernetes'  # default for yaml
        return 'unknown'
    
    def analyze_content(self, content: str, file_type: str) -> dict:
        """
        Analyze content for security patterns.
        
        Returns:
            {
                'permissive_findings': [...],
                'restrictive_findings': [...],
                'risk_score': int,
                'summary': str
            }
        """
        patterns = self.patterns_by_type.get(file_type, self.all_patterns)
        
        permissive = []
        restrictive = []
        
        for pattern in patterns:
            matches = pattern.matches(content)
            for match in matches:
                match['cwe_id'] = pattern.cwe_id
                match['category'] = pattern.category.value
                match['remediation'] = pattern.remediation
                
                if pattern.is_permissive:
                    permissive.append(match)
                else:
                    restrictive.append(match)
        
        # Calculate risk score
        risk_score = sum(
            self.severity_weights.get(Severity[f['severity']], 0) 
            for f in permissive
        )
        
        return {
            'permissive_findings': permissive,
            'restrictive_findings': restrictive,
            'risk_score': risk_score,
            'summary': f"Found {len(permissive)} issues, {len(restrictive)} safeguards, risk={risk_score}"
        }
    
    def analyze_posture_change(
        self, 
        before: str, 
        after: str, 
        file_type: str
    ) -> dict:
        """
        Analyze security posture change between two versions.
        
        This is the KEY method for Stream 2:
        Detects if security got weaker or stronger.
        """
        before_analysis = self.analyze_content(before, file_type)
        after_analysis = self.analyze_content(after, file_type)
        
        risk_delta = after_analysis['risk_score'] - before_analysis['risk_score']
        
        if risk_delta > 0:
            direction = PostureDirection.RESTRICTIVE_TO_PERMISSIVE
            summary = f"⚠️ SECURITY REGRESSION: Risk increased by {risk_delta}"
        elif risk_delta < 0:
            direction = PostureDirection.PERMISSIVE_TO_RESTRICTIVE
            summary = f"✅ SECURITY IMPROVEMENT: Risk decreased by {abs(risk_delta)}"
        else:
            direction = PostureDirection.NEUTRAL
            summary = "No significant change in security posture"
        
        return {
            'direction': direction.value,
            'risk_delta': risk_delta,
            'summary': summary,
            'before': {
                'risk_score': before_analysis['risk_score'],
                'issues': len(before_analysis['permissive_findings']),
                'safeguards': len(before_analysis['restrictive_findings']),
            },
            'after': {
                'risk_score': after_analysis['risk_score'],
                'issues': len(after_analysis['permissive_findings']),
                'safeguards': len(after_analysis['restrictive_findings']),
            },
            'before_findings': before_analysis,
            'after_findings': after_analysis,
        }
    
    def export_model(self, filename: str = 'threat_model.json'):
        """Export the threat model to JSON"""
        data = {
            'name': 'IaC Security Threat Model',
            'version': '1.0',
            'categories': [c.value for c in ThreatCategory],
            'severities': [s.name for s in Severity],
            'patterns': []
        }
        
        for pattern in self.all_patterns:
            data['patterns'].append({
                'id': pattern.id,
                'name': pattern.name,
                'description': pattern.description,
                'is_permissive': pattern.is_permissive,
                'severity': pattern.severity.name,
                'category': pattern.category.value,
                'cwe_id': pattern.cwe_id,
                'file_types': pattern.file_types,
                'regex': pattern.regex,
                'remediation': pattern.remediation,
            })
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"✅ Exported threat model to {filename}")
        return filename
    
    def print_summary(self):
        """Print a summary of the threat model"""
        print("""
╔══════════════════════════════════════════════════════════════════════╗
║                    IaC SECURITY THREAT MODEL                         ║
╠══════════════════════════════════════════════════════════════════════╣
""")
        
        for file_type, patterns in self.patterns_by_type.items():
            permissive = [p for p in patterns if p.is_permissive]
            restrictive = [p for p in patterns if not p.is_permissive]
            
            print(f"║  {file_type.upper():12}")
            print(f"║    Patterns: {len(patterns):3} total")
            print(f"║    Permissive (detect issues): {len(permissive):3}")
            print(f"║    Restrictive (detect safeguards): {len(restrictive):3}")
            print("║")
        
        print("╚══════════════════════════════════════════════════════════════════════╝")


# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    model = IaCThreatModel()
    model.print_summary()
    
    # Export the model
    model.export_model()
    
    # Demo: analyze some sample content
    sample_k8s = """
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    securityContext:
      privileged: true
      runAsUser: 0
      allowPrivilegeEscalation: true
    """
    
    print("\n📋 DEMO: Analyzing Kubernetes manifest...")
    result = model.analyze_content(sample_k8s, 'kubernetes')
    print(f"   {result['summary']}")
    for finding in result['permissive_findings']:
        print(f"   ⚠️ Line {finding['line_number']}: {finding['pattern_name']}")