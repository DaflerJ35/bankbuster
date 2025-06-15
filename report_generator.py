import json
import base64
from datetime import datetime
try:
    from jinja2 import Template
except ImportError:
    # Jinja2 is a dependency and should be installed via requirements.txt
    # If you see this error, run: pip install -r requirements.txt
    logging.error("Jinja2 not found. Please install dependencies: pip install -r requirements.txt")
    raise # Re-raise the ImportError so the application knows a critical dependency is missing
from models import ScanSession, Finding, Report, User, db
from crypto_utils import encrypt_data, decrypt_data
import logging

class ReportGenerator:
    def __init__(self):
        self.report_templates = {
            'executive': self._get_executive_template(),
            'technical': self._get_technical_template(),
            'compliance': self._get_compliance_template()
        }
    
    def generate_report(self, user_id, report_name, report_type, scan_session_ids):
        """Generate comprehensive security report"""
        try:
            # Collect data from scan sessions
            report_data = self._collect_report_data(scan_session_ids)
            
            # Generate report content based on type
            if report_type in self.report_templates:
                report_content = self._generate_report_content(report_type, report_data)
            else:
                raise ValueError(f"Unknown report type: {report_type}")
            
            # Create report record
            report = Report(
                user_id=user_id,
                report_name=report_name,
                report_type=report_type,
                scan_sessions=json.dumps(scan_session_ids),
                report_data=encrypt_data(json.dumps(report_content)),
                is_encrypted=True
            )
            
            db.session.add(report)
            db.session.commit()
            
            logging.info(f"Report generated: {report_name} (ID: {report.id})")
            return report.id
            
        except Exception as e:
            logging.error(f"Report generation failed: {str(e)}")
            return None
    
    def _collect_report_data(self, scan_session_ids):
        """Collect and organize data from scan sessions"""
        report_data = {
            'scan_sessions': [],
            'findings': [],
            'summary': {
                'total_sessions': len(scan_session_ids),
                'total_findings': 0,
                'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'finding_types': {},
                'scan_duration': 0
            },
            'targets': set(),
            'vulnerabilities': [],
            'recommendations': []
        }
        
        for session_id in scan_session_ids:
            session = ScanSession.query.get(session_id)
            if not session:
                continue
            
            # Session information
            session_data = {
                'id': session.id,
                'name': session.session_name,
                'type': session.scan_type,
                'status': session.status,
                'created_at': session.created_at.isoformat(),
                'updated_at': session.updated_at.isoformat()
            }
            
            # Decrypt target information
            if session.target_info:
                try:
                    target_data = json.loads(decrypt_data(session.target_info))
                    session_data['targets'] = target_data
                    report_data['targets'].update(target_data.get('hosts', []))
                except:
                    session_data['targets'] = 'Encrypted'
            
            report_data['scan_sessions'].append(session_data)
            
            # Collect findings
            findings = Finding.query.filter_by(scan_session_id=session_id).all()
            
            for finding in findings:
                finding_data = {
                    'id': finding.id,
                    'type': finding.finding_type,
                    'severity': finding.severity,
                    'title': finding.title,
                    'port': finding.target_port,
                    'cve_id': finding.cve_id,
                    'cvss_score': finding.cvss_score,
                    'created_at': finding.created_at.isoformat()
                }
                
                # Decrypt sensitive data
                try:
                    if finding.description:
                        finding_data['description'] = decrypt_data(finding.description)
                    if finding.target_host:
                        finding_data['target_host'] = decrypt_data(finding.target_host)
                    if finding.remediation:
                        finding_data['remediation'] = decrypt_data(finding.remediation)
                except:
                    finding_data['description'] = 'Encrypted'
                    finding_data['target_host'] = 'Encrypted'
                    finding_data['remediation'] = 'Encrypted'
                
                report_data['findings'].append(finding_data)
                
                # Update summary statistics
                report_data['summary']['total_findings'] += 1
                report_data['summary']['severity_counts'][finding.severity] += 1
                
                if finding.finding_type in report_data['summary']['finding_types']:
                    report_data['summary']['finding_types'][finding.finding_type] += 1
                else:
                    report_data['summary']['finding_types'][finding.finding_type] = 1
        
        # Convert targets set to list for JSON serialization
        report_data['targets'] = list(report_data['targets'])
        
        # Generate recommendations based on findings
        report_data['recommendations'] = self._generate_recommendations(report_data['findings'])
        
        return report_data
    
    def _generate_recommendations(self, findings):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Count findings by type and severity
        critical_findings = [f for f in findings if f['severity'] == 'critical']
        high_findings = [f for f in findings if f['severity'] == 'high']
        
        # Critical recommendations
        if critical_findings:
            recommendations.append({
                'priority': 'Critical',
                'title': 'Address Critical Vulnerabilities Immediately',
                'description': f'Found {len(critical_findings)} critical vulnerabilities that require immediate attention.',
                'action_items': [
                    'Prioritize patching of critical vulnerabilities',
                    'Implement emergency security measures',
                    'Monitor systems for signs of compromise',
                    'Consider taking affected systems offline if necessary'
                ]
            })
        
        # High priority recommendations
        if high_findings:
            recommendations.append({
                'priority': 'High',
                'title': 'Remediate High-Risk Issues',
                'description': f'Found {len(high_findings)} high-risk vulnerabilities that should be addressed promptly.',
                'action_items': [
                    'Schedule patching within 30 days',
                    'Implement compensating controls',
                    'Increase monitoring for affected systems',
                    'Update security procedures'
                ]
            })
        
        # General security recommendations
        finding_types = set(f['type'] for f in findings)
        
        if 'open_port' in finding_types:
            recommendations.append({
                'priority': 'Medium',
                'title': 'Improve Network Security',
                'description': 'Multiple open ports detected that may increase attack surface.',
                'action_items': [
                    'Review and close unnecessary ports',
                    'Implement firewall rules',
                    'Use network segmentation',
                    'Monitor network traffic'
                ]
            })
        
        if 'vulnerability' in finding_types:
            recommendations.append({
                'priority': 'Medium',
                'title': 'Enhance Vulnerability Management',
                'description': 'Various vulnerabilities identified in the environment.',
                'action_items': [
                    'Implement regular vulnerability scanning',
                    'Establish patch management process',
                    'Keep software and systems updated',
                    'Subscribe to security advisories'
                ]
            })
        
        if any('web' in f['type'] for f in findings):
            recommendations.append({
                'priority': 'Medium',
                'title': 'Strengthen Web Application Security',
                'description': 'Web application vulnerabilities detected.',
                'action_items': [
                    'Implement secure coding practices',
                    'Use web application firewalls',
                    'Regular security testing',
                    'Input validation and output encoding'
                ]
            })
        
        return recommendations
    
    def _generate_report_content(self, report_type, report_data):
        """Generate report content based on template"""
        template = Template(self.report_templates[report_type])
        
        # Add additional context
        context = {
            'report_data': report_data,
            'generation_date': datetime.utcnow().isoformat(),
            'total_targets': len(report_data['targets']),
            'risk_score': self._calculate_risk_score(report_data['findings'])
        }
        
        return template.render(**context)
    
    def _calculate_risk_score(self, findings):
        """Calculate overall risk score based on findings"""
        if not findings:
            return 0
        
        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
        
        total_score = sum(severity_weights.get(f['severity'], 0) for f in findings)
        max_possible_score = len(findings) * 10
        
        return min(100, int((total_score / max_possible_score) * 100)) if max_possible_score > 0 else 0
    
    def get_report(self, report_id, user_id):
        """Retrieve and decrypt report"""
        try:
            report = Report.query.filter_by(id=report_id, user_id=user_id).first()
            if not report:
                return None
            
            report_content = json.loads(decrypt_data(report.report_data))
            
            return {
                'id': report.id,
                'name': report.report_name,
                'type': report.report_type,
                'created_at': report.created_at.isoformat(),
                'content': report_content
            }
            
        except Exception as e:
            logging.error(f"Failed to retrieve report {report_id}: {str(e)}")
            return None
    
    def export_report(self, report_id, export_format='html'):
        """Export report in specified format"""
        try:
            report = Report.query.get(report_id)
            if not report:
                return None
            
            report_content = json.loads(decrypt_data(report.report_data))
            
            if export_format == 'html':
                return self._export_html(report_content, report.report_name)
            elif export_format == 'json':
                return self._export_json(report_content)
            elif export_format == 'csv':
                return self._export_csv(report_content)
            else:
                raise ValueError(f"Unsupported export format: {export_format}")
            
        except Exception as e:
            logging.error(f"Report export failed: {str(e)}")
            return None
    
    def _export_html(self, report_content, report_name):
        """Export report as HTML"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ report_name }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #2c3e50; color: white; padding: 20px; }
                .summary { background-color: #ecf0f1; padding: 15px; margin: 20px 0; }
                .finding { border-left: 4px solid #e74c3c; padding: 10px; margin: 10px 0; }
                .critical { border-color: #c0392b; }
                .high { border-color: #e74c3c; }
                .medium { border-color: #f39c12; }
                .low { border-color: #f1c40f; }
                .info { border-color: #3498db; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{{ report_name }}</h1>
                <p>Generated: {{ generation_date }}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p>Total Findings: {{ total_findings }}</p>
                <p>Risk Score: {{ risk_score }}/100</p>
            </div>
            
            <h2>Findings</h2>
            {% for finding in findings %}
            <div class="finding {{ finding.severity }}">
                <h3>{{ finding.title }}</h3>
                <p><strong>Severity:</strong> {{ finding.severity|title }}</p>
                <p><strong>Target:</strong> {{ finding.target_host }}</p>
                {% if finding.description %}
                <p><strong>Description:</strong> {{ finding.description }}</p>
                {% endif %}
                {% if finding.remediation %}
                <p><strong>Remediation:</strong> {{ finding.remediation }}</p>
                {% endif %}
            </div>
            {% endfor %}
        </body>
        </html>
        """
        
        template = Template(html_template)
        return template.render(
            report_name=report_name,
            generation_date=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            total_findings=len(report_content.get('findings', [])),
            risk_score=self._calculate_risk_score(report_content.get('findings', [])),
            findings=report_content.get('findings', [])
        )
    
    def _export_json(self, report_content):
        """Export report as JSON"""
        return json.dumps(report_content, indent=2)
    
    def _export_csv(self, report_content):
        """Export findings as CSV"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Title', 'Severity', 'Type', 'Target', 'Port', 'CVE ID', 'CVSS Score', 'Description'])
        
        # Write findings
        for finding in report_content.get('findings', []):
            writer.writerow([
                finding.get('title', ''),
                finding.get('severity', ''),
                finding.get('type', ''),
                finding.get('target_host', ''),
                finding.get('port', ''),
                finding.get('cve_id', ''),
                finding.get('cvss_score', ''),
                finding.get('description', '')
            ])
        
        return output.getvalue()
    
    def _get_executive_template(self):
        """Executive summary report template"""
        return """
# EXECUTIVE SUMMARY - SECURITY ASSESSMENT REPORT

**Report Generated:** {{ generation_date }}
**Assessment Period:** {{ report_data.scan_sessions[0].created_at if report_data.scan_sessions else 'N/A' }}
**Total Systems Tested:** {{ total_targets }}
**Overall Risk Score:** {{ risk_score }}/100

## KEY FINDINGS

**Critical Issues:** {{ report_data.summary.severity_counts.critical }}
**High Risk Issues:** {{ report_data.summary.severity_counts.high }}
**Medium Risk Issues:** {{ report_data.summary.severity_counts.medium }}
**Total Findings:** {{ report_data.summary.total_findings }}

## RISK ASSESSMENT

{% if risk_score >= 80 %}
**CRITICAL RISK:** Immediate action required to address security vulnerabilities.
{% elif risk_score >= 60 %}
**HIGH RISK:** Significant security issues require prompt attention.
{% elif risk_score >= 40 %}
**MEDIUM RISK:** Moderate security concerns should be addressed.
{% else %}
**LOW RISK:** Minor security improvements recommended.
{% endif %}

## RECOMMENDATIONS

{% for rec in report_data.recommendations %}
### {{ rec.priority }} Priority: {{ rec.title }}
{{ rec.description }}

Action Items:
{% for item in rec.action_items %}
- {{ item }}
{% endfor %}

{% endfor %}

## CONCLUSION

This assessment identified {{ report_data.summary.total_findings }} security issues across {{ total_targets }} targets. 
Immediate attention should be given to critical and high-severity findings to reduce organizational risk.
        """
    
    def _get_technical_template(self):
        """Technical detailed report template"""
        return """
# TECHNICAL SECURITY ASSESSMENT REPORT

**Report Generated:** {{ generation_date }}
**Total Scan Sessions:** {{ report_data.summary.total_sessions }}
**Total Findings:** {{ report_data.summary.total_findings }}

## SCAN SUMMARY

{% for session in report_data.scan_sessions %}
### Scan Session: {{ session.name }}
- **Type:** {{ session.type }}
- **Status:** {{ session.status }}
- **Started:** {{ session.created_at }}
- **Completed:** {{ session.updated_at }}
{% endfor %}

## DETAILED FINDINGS

{% for finding in report_data.findings %}
### Finding #{{ loop.index }}: {{ finding.title }}

**Severity:** {{ finding.severity|upper }}
**Type:** {{ finding.type }}
**Target:** {{ finding.target_host }}
{% if finding.port %}**Port:** {{ finding.port }}{% endif %}
{% if finding.cve_id %}**CVE ID:** {{ finding.cve_id }}{% endif %}
{% if finding.cvss_score %}**CVSS Score:** {{ finding.cvss_score }}{% endif %}

**Description:**
{{ finding.description }}

{% if finding.remediation %}
**Remediation:**
{{ finding.remediation }}
{% endif %}

---
{% endfor %}

## TECHNICAL RECOMMENDATIONS

{% for rec in report_data.recommendations %}
### {{ rec.title }}
{{ rec.description }}

**Action Items:**
{% for item in rec.action_items %}
- {{ item }}
{% endfor %}

{% endfor %}
        """
    
    def _get_compliance_template(self):
        """Compliance-focused report template"""
        return """
# COMPLIANCE SECURITY ASSESSMENT REPORT

**Report Generated:** {{ generation_date }}
**Assessment Scope:** {{ total_targets }} systems
**Total Issues Identified:** {{ report_data.summary.total_findings }}

## COMPLIANCE SUMMARY

### Risk Distribution
- **Critical:** {{ report_data.summary.severity_counts.critical }} findings
- **High:** {{ report_data.summary.severity_counts.high }} findings  
- **Medium:** {{ report_data.summary.severity_counts.medium }} findings
- **Low:** {{ report_data.summary.severity_counts.low }} findings

## REGULATORY CONSIDERATIONS

### Critical Security Controls
{% for finding in report_data.findings %}
{% if finding.severity in ['critical', 'high'] %}
- **{{ finding.title }}** ({{ finding.severity|title }})
  - System: {{ finding.target_host }}
  - Impact: Potential compliance violation
{% endif %}
{% endfor %}

## REMEDIATION ROADMAP

{% for rec in report_data.recommendations %}
### Phase {{ loop.index }}: {{ rec.title }}
**Priority:** {{ rec.priority }}
**Timeline:** {% if rec.priority == 'Critical' %}Immediate{% elif rec.priority == 'High' %}30 days{% else %}90 days{% endif %}

{{ rec.description }}

**Required Actions:**
{% for item in rec.action_items %}
- {{ item }}
{% endfor %}

{% endfor %}

## COMPLIANCE STATUS

Based on this assessment:
- **{{ report_data.summary.severity_counts.critical + report_data.summary.severity_counts.high }}** high-priority issues require immediate attention for compliance
- **{{ report_data.summary.severity_counts.medium }}** medium-priority issues should be addressed in the next compliance cycle
- Regular assessments recommended to maintain compliance posture
        """
