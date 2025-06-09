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

# Initialize military-grade advanced systems
try:
    from secure_runtime import secure_runtime
    from p2p_mesh import mesh_network
    from ops_modules import execute_module, get_available_modules
    from agent_mutation import mutation_engine, stealth_chain
    from failsafe_system import failsafe_system
    from voice_command import voice_engine
    advanced_systems_enabled = True
except ImportError as e:
    advanced_systems_enabled = False
    logging.warning(f"Advanced systems not available: {str(e)}")

# Fix missing datetime import
from datetime import datetime, timedelta

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

# ===============================
# ADVANCED AI-POWERED FEATURES
# ===============================

@main_bp.route('/ai-intelligence')
@login_required
def ai_intelligence_page():
    """AI-powered vulnerability intelligence interface"""
    if not ai_enabled:
        flash('AI Intelligence module is not available', 'warning')
        return redirect(url_for('main.dashboard'))
    
    return render_template('ai_intelligence.html')

@main_bp.route('/start-ai-analysis', methods=['POST'])
@login_required
def start_ai_analysis():
    """Start AI-powered vulnerability analysis"""
    if not ai_enabled:
        return jsonify({'error': 'AI Intelligence not available'}), 503
    
    try:
        if current_user.role not in ['admin', 'operator']:
            return jsonify({'error': 'Insufficient privileges'}), 403
        
        session_id = request.form.get('session_id')
        target_data = request.form.get('target_data')
        
        if not session_id:
            return jsonify({'error': 'Session ID required'}), 400
        
        # Parse target data
        try:
            target_info = json.loads(target_data) if target_data else {}
        except json.JSONDecodeError:
            return jsonify({'error': 'Invalid target data format'}), 400
        
        # Start AI analysis in background
        def run_ai_analysis():
            try:
                result = ai_intelligence.analyze_target(session_id, target_info)
                logging.info(f"AI analysis completed for session {session_id}")
            except Exception as e:
                logging.error(f"AI analysis failed: {str(e)}")
        
        analysis_thread = threading.Thread(target=run_ai_analysis, daemon=True)
        analysis_thread.start()
        
        flash('AI-powered vulnerability analysis started', 'success')
        return jsonify({'success': True, 'message': 'AI analysis initiated'})
    
    except Exception as e:
        logging.error(f"AI analysis start error: {str(e)}")
        return jsonify({'error': 'Failed to start AI analysis'}), 500

@main_bp.route('/threat-hunting')
@login_required
def threat_hunting_page():
    """Advanced threat hunting interface"""
    if not threat_hunting_enabled:
        flash('Threat Hunting module is not available', 'warning')
        return redirect(url_for('main.dashboard'))
    
    return render_template('threat_hunting.html')

@main_bp.route('/start-threat-hunt', methods=['POST'])
@login_required
def start_threat_hunt():
    """Start advanced threat hunting session"""
    if not threat_hunting_enabled:
        return jsonify({'error': 'Threat Hunting not available'}), 503
    
    try:
        if current_user.role not in ['admin', 'operator']:
            return jsonify({'error': 'Insufficient privileges'}), 403
        
        hunt_type = request.form.get('hunt_type', 'comprehensive')
        hunt_config = {
            'type': hunt_type,
            'targets': request.form.getlist('targets'),
            'duration': int(request.form.get('duration', 3600)),  # 1 hour default
            'stealth_level': request.form.get('stealth_level', 'medium')
        }
        
        hunt_id = threat_hunter.start_threat_hunt(hunt_config)
        
        # Log threat hunting activity
        audit_log = AuditLog(
            user_id=current_user.id,
            action='threat_hunt_started',
            target=f'Hunt ID: {hunt_id}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        audit_log.set_encrypted_details({
            'hunt_type': hunt_type,
            'hunt_id': hunt_id,
            'config': hunt_config
        })
        db.session.add(audit_log)
        db.session.commit()
        
        flash(f'Threat hunting session started: {hunt_id}', 'success')
        return jsonify({'success': True, 'hunt_id': hunt_id})
    
    except Exception as e:
        logging.error(f"Threat hunt start error: {str(e)}")
        return jsonify({'error': 'Failed to start threat hunt'}), 500

@main_bp.route('/api/threat-hunt-status/<hunt_id>')
@login_required
def api_threat_hunt_status(hunt_id):
    """API endpoint for threat hunt status"""
    if not threat_hunting_enabled:
        return jsonify({'error': 'Threat Hunting not available'}), 503
    
    try:
        status = threat_hunter.get_hunt_status(hunt_id)
        return jsonify(status)
    
    except Exception as e:
        logging.error(f"Threat hunt status error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@main_bp.route('/autonomous-operations')
@login_required
def autonomous_operations_page():
    """Autonomous red team operations interface"""
    if not autonomous_enabled:
        flash('Autonomous Red Team module is not available', 'warning')
        return redirect(url_for('main.dashboard'))
    
    return render_template('autonomous_operations.html')

@main_bp.route('/start-autonomous-operation', methods=['POST'])
@login_required
def start_autonomous_operation():
    """Start fully autonomous red team operation"""
    if not autonomous_enabled:
        return jsonify({'error': 'Autonomous Red Team not available'}), 503
    
    try:
        if current_user.role != 'admin':  # Only admins can start autonomous operations
            return jsonify({'error': 'Admin privileges required'}), 403
        
        operation_config = {
            'targets': request.form.getlist('targets'),
            'objectives': [
                {'type': obj_type, 'priority': priority} 
                for obj_type, priority in zip(
                    request.form.getlist('objective_types'),
                    request.form.getlist('objective_priorities')
                )
            ],
            'stealth_level': request.form.get('stealth_level', 'medium'),
            'automation_level': request.form.get('automation_level', 'full'),
            'success_threshold': float(request.form.get('success_threshold', 0.8)),
            'max_duration': int(request.form.get('max_duration', 14400)),  # 4 hours default
            'learning_enabled': request.form.get('learning_enabled') == 'on',
            'auto_cleanup': request.form.get('auto_cleanup') == 'on'
        }
        
        operation_id = autonomous_engine.start_autonomous_operation(operation_config)
        
        # Log autonomous operation
        audit_log = AuditLog(
            user_id=current_user.id,
            action='autonomous_operation_started',
            target=f'Operation ID: {operation_id}',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        audit_log.set_encrypted_details({
            'operation_id': operation_id,
            'config': operation_config
        })
        db.session.add(audit_log)
        db.session.commit()
        
        flash(f'Autonomous red team operation started: {operation_id}', 'success')
        return jsonify({'success': True, 'operation_id': operation_id})
    
    except Exception as e:
        logging.error(f"Autonomous operation start error: {str(e)}")
        return jsonify({'error': 'Failed to start autonomous operation'}), 500

@main_bp.route('/api/autonomous-operation-status/<operation_id>')
@login_required
def api_autonomous_operation_status(operation_id):
    """API endpoint for autonomous operation status"""
    if not autonomous_enabled:
        return jsonify({'error': 'Autonomous Red Team not available'}), 503
    
    try:
        status = autonomous_engine.get_operation_status(operation_id)
        return jsonify(status)
    
    except Exception as e:
        logging.error(f"Autonomous operation status error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@main_bp.route('/advanced-payloads')
@login_required
def advanced_payloads_page():
    """Advanced payload generation interface"""
    return render_template('advanced_payloads.html')

@main_bp.route('/generate-payload', methods=['POST'])
@login_required
def generate_payload():
    """Generate advanced evasive payload"""
    try:
        if current_user.role not in ['admin', 'operator']:
            return jsonify({'error': 'Insufficient privileges'}), 403
        
        payload_config = {
            'type': request.form.get('payload_type', 'reverse_shell'),
            'os': request.form.get('target_os', 'linux'),
            'evasion_level': request.form.get('evasion_level', 'medium'),
            'delivery': request.form.get('delivery_method', 'binary'),
            'lhost': request.form.get('lhost', '127.0.0.1'),
            'lport': int(request.form.get('lport', 4444))
        }
        
        # Import here to avoid startup issues
        from advanced_payloads import payload_generator
        payload_result = payload_generator.generate_payload(payload_config)
        
        # Log payload generation
        audit_log = AuditLog(
            user_id=current_user.id,
            action='payload_generated',
            target=payload_config['type'],
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        audit_log.set_encrypted_details({
            'payload_type': payload_config['type'],
            'target_os': payload_config['os'],
            'evasion_level': payload_config['evasion_level'],
            'payload_hash': payload_result.get('hash', 'unknown')
        })
        db.session.add(audit_log)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'payload': payload_result['payload'],
            'instructions': payload_result['instructions'],
            'hash': payload_result.get('hash', ''),
            'size': payload_result.get('size', 0)
        })
    
    except Exception as e:
        logging.error(f"Payload generation error: {str(e)}")
        return jsonify({'error': 'Failed to generate payload'}), 500

@main_bp.route('/behavioral-analysis')
@login_required
def behavioral_analysis_page():
    """Behavioral analysis and insider threat detection"""
    return render_template('behavioral_analysis.html')

@main_bp.route('/api/behavioral-analytics')
@login_required
def api_behavioral_analytics():
    """API endpoint for behavioral analytics data"""
    try:
        # Get recent user activity patterns
        recent_logs = AuditLog.query.filter(
            AuditLog.timestamp >= datetime.utcnow() - timedelta(days=7)
        ).order_by(AuditLog.timestamp.desc()).limit(1000).all()
        
        # Analyze patterns
        user_activity = {}
        for log in recent_logs:
            user_id = log.user_id
            if user_id not in user_activity:
                user_activity[user_id] = {
                    'total_actions': 0,
                    'unique_actions': set(),
                    'peak_hours': [],
                    'risk_score': 0.0
                }
            
            user_activity[user_id]['total_actions'] += 1
            user_activity[user_id]['unique_actions'].add(log.action)
            user_activity[user_id]['peak_hours'].append(log.timestamp.hour)
        
        # Calculate risk scores
        for user_id, activity in user_activity.items():
            activity['unique_actions'] = len(activity['unique_actions'])
            
            # Simple risk scoring based on activity patterns
            if activity['total_actions'] > 100:  # High activity
                activity['risk_score'] += 0.3
            if activity['unique_actions'] > 20:  # Many different actions
                activity['risk_score'] += 0.2
            
            # Check for off-hours activity
            off_hours = [h for h in activity['peak_hours'] if h < 6 or h > 22]
            if len(off_hours) > len(activity['peak_hours']) * 0.3:
                activity['risk_score'] += 0.4
            
            activity['peak_hours'] = list(set(activity['peak_hours']))
        
        return jsonify({
            'user_activity': user_activity,
            'total_users_analyzed': len(user_activity),
            'high_risk_users': [
                uid for uid, data in user_activity.items() 
                if data['risk_score'] > 0.6
            ]
        })
    
    except Exception as e:
        logging.error(f"Behavioral analytics error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
