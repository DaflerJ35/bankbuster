from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import login_required, current_user
from models import ScanSession, Finding, Report, NetworkTarget, AuditLog, User
from app import db
from network_scanner import NetworkScanner
from vulnerability_scanner import VulnerabilityScanner
from exploit_framework import ExploitFramework
from web_security_tester import WebSecurityTester
from report_generator import ReportGenerator
from anonymity_manager import AnonymityManager
from crypto_utils import encrypt_data, decrypt_data
import json
import threading
from datetime import datetime
import logging

main_bp = Blueprint('main', __name__)

# Initialize scanners and managers
network_scanner = NetworkScanner()
vulnerability_scanner = VulnerabilityScanner()
exploit_framework = ExploitFramework()
web_security_tester = WebSecurityTester()
report_generator = ReportGenerator()
anonymity_manager = AnonymityManager()

# Initialize advanced components with error handling
try:
    from ai_intelligence import ai_intelligence
    ai_enabled = True
except ImportError:
    ai_enabled = False
    logging.warning("AI Intelligence module not available")

try:
    from threat_hunting import threat_hunter
    threat_hunting_enabled = True
except ImportError:
    threat_hunting_enabled = False
    logging.warning("Threat Hunting module not available")

try:
    from autonomous_red_team import autonomous_engine
    autonomous_enabled = True
except ImportError:
    autonomous_enabled = False
    logging.warning("Autonomous Red Team module not available")

@main_bp.route('/')
@login_required
def dashboard():
    """Main dashboard"""
    try:
        # Get recent scan sessions
        recent_sessions = ScanSession.query.filter_by(user_id=current_user.id)\
                                         .order_by(ScanSession.created_at.desc())\
                                         .limit(5).all()
        
        # Get findings summary
        total_findings = Finding.query.join(ScanSession)\
                               .filter(ScanSession.user_id == current_user.id).count()
        
        critical_findings = Finding.query.join(ScanSession)\
                                  .filter(ScanSession.user_id == current_user.id,
                                         Finding.severity == 'critical').count()
        
        high_findings = Finding.query.join(ScanSession)\
                              .filter(ScanSession.user_id == current_user.id,
                                     Finding.severity == 'high').count()
        
        # Get anonymity status
        anonymity_status = anonymity_manager.get_anonymity_status()
        
        # Recent reports
        recent_reports = Report.query.filter_by(user_id=current_user.id)\
                              .order_by(Report.created_at.desc())\
                              .limit(3).all()
        
        return render_template('dashboard.html',
                             recent_sessions=recent_sessions,
                             total_findings=total_findings,
                             critical_findings=critical_findings,
                             high_findings=high_findings,
                             anonymity_status=anonymity_status,
                             recent_reports=recent_reports)
    
    except Exception as e:
        logging.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard data', 'danger')
        return render_template('dashboard.html')

@main_bp.route('/network-scan')
@login_required
def network_scan():
    """Network scanning interface"""
    return render_template('network_scan.html')

@main_bp.route('/start-network-scan', methods=['POST'])
@login_required
def start_network_scan():
    """Start network scan"""
    try:
        scan_name = request.form.get('scan_name')
        targets = request.form.get('targets', '').split('\n')
        scan_type = request.form.get('scan_type', 'basic')
        use_anonymity = request.form.get('use_anonymity') == 'on'
        
        # Clean and validate targets
        targets = [t.strip() for t in targets if t.strip()]
        if not targets:
            flash('No valid targets specified', 'danger')
            return redirect(url_for('main.network_scan'))
        
        # Create scan session
        scan_session = ScanSession(
            user_id=current_user.id,
            session_name=scan_name,
            target_info=encrypt_data(json.dumps({'hosts': targets, 'type': 'network'})),
            scan_type='network',
            status='pending'
        )
        
        db.session.add(scan_session)
        db.session.commit()
        
        # Log scan start
        audit_log = AuditLog(
            user_id=current_user.id,
            action='NETWORK_SCAN_STARTED',
            target=f'Targets: {len(targets)} hosts',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        audit_log.set_encrypted_details({
            'scan_id': scan_session.id,
            'scan_name': scan_name,
            'targets_count': len(targets),
            'scan_type': scan_type,
            'anonymity_enabled': use_anonymity
        })
        db.session.add(audit_log)
        db.session.commit()
        
        # Start scan in background thread
        def run_scan():
            network_scanner.scan_network(scan_session.id, targets, scan_type, use_anonymity)
        
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()
        
        flash(f'Network scan "{scan_name}" started successfully', 'success')
        return redirect(url_for('main.scan_status', session_id=scan_session.id))
    
    except Exception as e:
        logging.error(f"Network scan start failed: {str(e)}")
        flash('Failed to start network scan', 'danger')
        return redirect(url_for('main.network_scan'))

@main_bp.route('/vulnerability-scan')
@login_required
def vulnerability_scan():
    """Vulnerability scanning interface"""
    return render_template('vulnerability_scan.html')

@main_bp.route('/start-vulnerability-scan', methods=['POST'])
@login_required
def start_vulnerability_scan():
    """Start vulnerability scan"""
    try:
        scan_name = request.form.get('scan_name')
        targets = request.form.get('targets', '').split('\n')
        use_anonymity = request.form.get('use_anonymity') == 'on'
        
        # Clean targets
        targets = [t.strip() for t in targets if t.strip()]
        if not targets:
            flash('No valid targets specified', 'danger')
            return redirect(url_for('main.vulnerability_scan'))
        
        # Create scan session
        scan_session = ScanSession(
            user_id=current_user.id,
            session_name=scan_name,
            target_info=encrypt_data(json.dumps({'hosts': targets, 'type': 'vulnerability'})),
            scan_type='vulnerability',
            status='pending'
        )
        
        db.session.add(scan_session)
        db.session.commit()
        
        # Log scan start
        audit_log = AuditLog(
            user_id=current_user.id,
            action='VULNERABILITY_SCAN_STARTED',
            target=f'Targets: {len(targets)} hosts',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        audit_log.set_encrypted_details({
            'scan_id': scan_session.id,
            'scan_name': scan_name,
            'targets_count': len(targets),
            'anonymity_enabled': use_anonymity
        })
        db.session.add(audit_log)
        db.session.commit()
        
        # Start scan
        def run_scan():
            scan_config = {'use_anonymity': use_anonymity}
            vulnerability_scanner.scan_vulnerabilities(scan_session.id, targets, scan_config)
        
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()
        
        flash(f'Vulnerability scan "{scan_name}" started successfully', 'success')
        return redirect(url_for('main.scan_status', session_id=scan_session.id))
    
    except Exception as e:
        logging.error(f"Vulnerability scan start failed: {str(e)}")
        flash('Failed to start vulnerability scan', 'danger')
        return redirect(url_for('main.vulnerability_scan'))

@main_bp.route('/exploit-framework')
@login_required
def exploit_framework_page():
    """Exploit framework interface"""
    available_exploits = exploit_framework.get_available_exploits()
    return render_template('exploit_framework.html', available_exploits=available_exploits)

@main_bp.route('/execute-exploit', methods=['POST'])
@login_required
def execute_exploit():
    """Execute exploit"""
    try:
        if current_user.role not in ['admin', 'operator']:
            flash('Insufficient privileges for exploit execution', 'danger')
            return redirect(url_for('main.exploit_framework_page'))
        
        exploit_name = request.form.get('exploit_name')
        target = request.form.get('target')
        use_anonymity = request.form.get('use_anonymity') == 'on'
        
        if not target:
            flash('Target is required', 'danger')
            return redirect(url_for('main.exploit_framework_page'))
        
        # Create scan session for exploit
        scan_session = ScanSession(
            user_id=current_user.id,
            session_name=f'Exploit: {exploit_name}',
            target_info=encrypt_data(json.dumps({'target': target, 'type': 'exploit'})),
            scan_type='exploit',
            status='pending'
        )
        
        db.session.add(scan_session)
        db.session.commit()
        
        # Log exploit execution
        audit_log = AuditLog(
            user_id=current_user.id,
            action='EXPLOIT_EXECUTED',
            target=f'Target: {target}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        audit_log.set_encrypted_details({
            'scan_id': scan_session.id,
            'exploit_name': exploit_name,
            'target': target,
            'anonymity_enabled': use_anonymity
        })
        db.session.add(audit_log)
        db.session.commit()
        
        # Execute exploit
        def run_exploit():
            exploit_config = {'use_anonymity': use_anonymity}
            exploit_framework.execute_exploit(scan_session.id, target, exploit_name, exploit_config)
        
        exploit_thread = threading.Thread(target=run_exploit)
        exploit_thread.daemon = True
        exploit_thread.start()
        
        flash(f'Exploit "{exploit_name}" executed against {target}', 'info')
        return redirect(url_for('main.scan_status', session_id=scan_session.id))
    
    except Exception as e:
        logging.error(f"Exploit execution failed: {str(e)}")
        flash('Failed to execute exploit', 'danger')
        return redirect(url_for('main.exploit_framework_page'))

@main_bp.route('/web-security')
@login_required
def web_security():
    """Web security testing interface"""
    return render_template('web_security.html')

@main_bp.route('/start-web-security-test', methods=['POST'])
@login_required
def start_web_security_test():
    """Start web security test"""
    try:
        scan_name = request.form.get('scan_name')
        target_url = request.form.get('target_url')
        use_anonymity = request.form.get('use_anonymity') == 'on'
        
        if not target_url:
            flash('Target URL is required', 'danger')
            return redirect(url_for('main.web_security'))
        
        # Create scan session
        scan_session = ScanSession(
            user_id=current_user.id,
            session_name=scan_name,
            target_info=encrypt_data(json.dumps({'url': target_url, 'type': 'web_security'})),
            scan_type='web_app',
            status='pending'
        )
        
        db.session.add(scan_session)
        db.session.commit()
        
        # Log scan start
        audit_log = AuditLog(
            user_id=current_user.id,
            action='WEB_SECURITY_SCAN_STARTED',
            target=f'URL: {target_url}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        audit_log.set_encrypted_details({
            'scan_id': scan_session.id,
            'scan_name': scan_name,
            'target_url': target_url,
            'anonymity_enabled': use_anonymity
        })
        db.session.add(audit_log)
        db.session.commit()
        
        # Start web security test
        def run_test():
            test_config = {'use_anonymity': use_anonymity}
            web_security_tester.comprehensive_web_test(scan_session.id, target_url, test_config)
        
        test_thread = threading.Thread(target=run_test)
        test_thread.daemon = True
        test_thread.start()
        
        flash(f'Web security test "{scan_name}" started successfully', 'success')
        return redirect(url_for('main.scan_status', session_id=scan_session.id))
    
    except Exception as e:
        logging.error(f"Web security test start failed: {str(e)}")
        flash('Failed to start web security test', 'danger')
        return redirect(url_for('main.web_security'))

@main_bp.route('/scan-status/<int:session_id>')
@login_required
def scan_status(session_id):
    """View scan status and results"""
    try:
        scan_session = ScanSession.query.filter_by(id=session_id, user_id=current_user.id).first()
        if not scan_session:
            flash('Scan session not found', 'danger')
            return redirect(url_for('main.dashboard'))
        
        # Get findings
        findings = Finding.query.filter_by(scan_session_id=session_id).all()
        
        # Decrypt findings for display
        decrypted_findings = []
        for finding in findings:
            finding_data = {
                'id': finding.id,
                'type': finding.finding_type,
                'severity': finding.severity,
                'title': finding.title,
                'port': finding.target_port,
                'cve_id': finding.cve_id,
                'cvss_score': finding.cvss_score,
                'created_at': finding.created_at
            }
            
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
            
            decrypted_findings.append(finding_data)
        
        return render_template('scan_status.html',
                             scan_session=scan_session,
                             findings=decrypted_findings)
    
    except Exception as e:
        logging.error(f"Scan status error: {str(e)}")
        flash('Error loading scan status', 'danger')
        return redirect(url_for('main.dashboard'))

@main_bp.route('/reports')
@login_required
def reports():
    """Reports interface"""
    try:
        # Get user's scan sessions for report generation
        scan_sessions = ScanSession.query.filter_by(user_id=current_user.id)\
                                        .order_by(ScanSession.created_at.desc()).all()
        
        # Get existing reports
        user_reports = Report.query.filter_by(user_id=current_user.id)\
                                 .order_by(Report.created_at.desc()).all()
        
        return render_template('reports.html',
                             scan_sessions=scan_sessions,
                             user_reports=user_reports)
    
    except Exception as e:
        logging.error(f"Reports page error: {str(e)}")
        flash('Error loading reports', 'danger')
        return render_template('reports.html', scan_sessions=[], user_reports=[])

@main_bp.route('/generate-report', methods=['POST'])
@login_required
def generate_report():
    """Generate security report"""
    try:
        report_name = request.form.get('report_name')
        report_type = request.form.get('report_type')
        session_ids = request.form.getlist('session_ids')
        
        if not session_ids:
            flash('No scan sessions selected', 'danger')
            return redirect(url_for('main.reports'))
        
        # Convert to integers
        session_ids = [int(sid) for sid in session_ids]
        
        # Generate report
        report_id = report_generator.generate_report(
            current_user.id, report_name, report_type, session_ids
        )
        
        if report_id:
            # Log report generation
            audit_log = AuditLog(
                user_id=current_user.id,
                action='REPORT_GENERATED',
                target=f'Report: {report_name}',
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            audit_log.set_encrypted_details({
                'report_id': report_id,
                'report_name': report_name,
                'report_type': report_type,
                'session_count': len(session_ids)
            })
            db.session.add(audit_log)
            db.session.commit()
            
            flash(f'Report "{report_name}" generated successfully', 'success')
        else:
            flash('Failed to generate report', 'danger')
        
        return redirect(url_for('main.reports'))
    
    except Exception as e:
        logging.error(f"Report generation failed: {str(e)}")
        flash('Failed to generate report', 'danger')
        return redirect(url_for('main.reports'))

@main_bp.route('/view-report/<int:report_id>')
@login_required
def view_report(report_id):
    """View generated report"""
    try:
        report_data = report_generator.get_report(report_id, current_user.id)
        if not report_data:
            flash('Report not found', 'danger')
            return redirect(url_for('main.reports'))
        
        return render_template('view_report.html', report=report_data)
    
    except Exception as e:
        logging.error(f"Report view error: {str(e)}")
        flash('Error loading report', 'danger')
        return redirect(url_for('main.reports'))

@main_bp.route('/export-report/<int:report_id>/<format>')
@login_required
def export_report(report_id, format):
    """Export report in specified format"""
    try:
        from flask import Response
        
        report_content = report_generator.export_report(report_id, format)
        if not report_content:
            flash('Failed to export report', 'danger')
            return redirect(url_for('main.reports'))
        
        # Set content type based on format
        content_types = {
            'html': 'text/html',
            'json': 'application/json',
            'csv': 'text/csv'
        }
        
        content_type = content_types.get(format, 'text/plain')
        
        return Response(
            report_content,
            mimetype=content_type,
            headers={
                'Content-Disposition': f'attachment; filename=report_{report_id}.{format}'
            }
        )
    
    except Exception as e:
        logging.error(f"Report export error: {str(e)}")
        flash('Error exporting report', 'danger')
        return redirect(url_for('main.reports'))

@main_bp.route('/settings')
@login_required
def settings():
    """User settings and configuration"""
    return render_template('settings.html')

@main_bp.route('/api/scan-progress/<int:session_id>')
@login_required
def api_scan_progress(session_id):
    """API endpoint for scan progress"""
    try:
        scan_session = ScanSession.query.filter_by(id=session_id, user_id=current_user.id).first()
        if not scan_session:
            return jsonify({'error': 'Scan session not found'}), 404
        
        findings_count = Finding.query.filter_by(scan_session_id=session_id).count()
        
        return jsonify({
            'status': scan_session.status,
            'findings_count': findings_count,
            'updated_at': scan_session.updated_at.isoformat()
        })
    
    except Exception as e:
        logging.error(f"Scan progress API error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@main_bp.route('/api/anonymity-status')
@login_required
def api_anonymity_status():
    """API endpoint for anonymity status"""
    try:
        status = anonymity_manager.get_anonymity_status()
        return jsonify(status)
    
    except Exception as e:
        logging.error(f"Anonymity status API error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@main_bp.route('/api/rotate-tor-circuit', methods=['POST'])
@login_required
def api_rotate_tor_circuit():
    """API endpoint to rotate Tor circuit"""
    try:
        if current_user.role not in ['admin', 'operator']:
            return jsonify({'error': 'Insufficient privileges'}), 403
        
        success = anonymity_manager.rotate_tor_circuit()
        return jsonify({'success': success})
    
    except Exception as e:
        logging.error(f"Tor circuit rotation error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
