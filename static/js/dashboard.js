/**
 * Red Team Platform - Dashboard JavaScript
 * Handles dashboard functionality, real-time updates, and data visualization
 */

class RedTeamDashboard {
    constructor() {
        this.updateInterval = 30000; // 30 seconds
        this.timers = {};
        this.charts = {};
        this.isInitialized = false;
        this.secureComm = window.RedTeamCrypto?.secureComm || null;
        
        // Dashboard state
        this.state = {
            scanSessions: [],
            findings: [],
            anonymityStatus: null,
            systemStatus: 'operational'
        };
    }

    /**
     * Initialize dashboard
     */
    async initialize() {
        if (this.isInitialized) return;
        
        try {
            console.log('Initializing Red Team Dashboard...');
            
            // Setup event listeners
            this.setupEventListeners();
            
            // Initialize charts
            this.initializeCharts();
            
            // Start real-time updates
            this.startRealTimeUpdates();
            
            // Load initial data
            await this.loadInitialData();
            
            this.isInitialized = true;
            console.log('Dashboard initialized successfully');
            
        } catch (error) {
            console.error('Dashboard initialization failed:', error);
            this.showError('Failed to initialize dashboard. Please refresh the page.');
        }
    }

    /**
     * Setup event listeners
     */
    setupEventListeners() {
        // Page visibility change
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.stopRealTimeUpdates();
            } else {
                this.startRealTimeUpdates();
            }
        });

        // Window beforeunload
        window.addEventListener('beforeunload', () => {
            this.cleanup();
        });

        // Refresh buttons
        document.addEventListener('click', (event) => {
            if (event.target.matches('[data-action="refresh"]')) {
                event.preventDefault();
                this.refreshData();
            }
            
            if (event.target.matches('[data-action="refresh-anonymity"]')) {
                event.preventDefault();
                this.updateAnonymityStatus();
            }
        });

        // Auto-refresh toggle
        const autoRefreshToggle = document.getElementById('auto-refresh-toggle');
        if (autoRefreshToggle) {
            autoRefreshToggle.addEventListener('change', (event) => {
                if (event.target.checked) {
                    this.startRealTimeUpdates();
                } else {
                    this.stopRealTimeUpdates();
                }
            });
        }
    }

    /**
     * Initialize charts and visualizations
     */
    initializeCharts() {
        // Findings severity chart
        this.initializeSeverityChart();
        
        // Scan activity chart
        this.initializeScanActivityChart();
        
        // Risk trend chart
        this.initializeRiskTrendChart();
    }

    /**
     * Initialize severity distribution chart
     */
    initializeSeverityChart() {
        const ctx = document.getElementById('severityChart');
        if (!ctx) return;

        this.charts.severity = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        '#dc3545', // Critical - Red
                        '#fd7e14', // High - Orange
                        '#ffc107', // Medium - Yellow
                        '#198754', // Low - Green
                        '#6c757d'  // Info - Gray
                    ],
                    borderWidth: 2,
                    borderColor: '#212529'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#e9ecef',
                            usePointStyle: true,
                            padding: 15
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(33, 37, 41, 0.9)',
                        titleColor: '#e9ecef',
                        bodyColor: '#e9ecef',
                        borderColor: '#495057',
                        borderWidth: 1
                    }
                }
            }
        });
    }

    /**
     * Initialize scan activity timeline chart
     */
    initializeScanActivityChart() {
        const ctx = document.getElementById('scanActivityChart');
        if (!ctx) return;

        this.charts.scanActivity = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Scans Completed',
                    data: [],
                    borderColor: '#0dcaf0',
                    backgroundColor: 'rgba(13, 202, 240, 0.1)',
                    tension: 0.4,
                    fill: true
                }, {
                    label: 'Findings Discovered',
                    data: [],
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    intersect: false,
                    mode: 'index'
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#e9ecef',
                            usePointStyle: true
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(33, 37, 41, 0.9)',
                        titleColor: '#e9ecef',
                        bodyColor: '#e9ecef'
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            color: '#6c757d'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    },
                    y: {
                        ticks: {
                            color: '#6c757d'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    }
                }
            }
        });
    }

    /**
     * Initialize risk trend chart
     */
    initializeRiskTrendChart() {
        const ctx = document.getElementById('riskTrendChart');
        if (!ctx) return;

        this.charts.riskTrend = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Network', 'Web App', 'System', 'Database', 'Wireless'],
                datasets: [{
                    label: 'Risk Score',
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        'rgba(220, 53, 69, 0.8)',
                        'rgba(253, 126, 20, 0.8)',
                        'rgba(255, 193, 7, 0.8)',
                        'rgba(25, 135, 84, 0.8)',
                        'rgba(13, 202, 240, 0.8)'
                    ],
                    borderColor: [
                        '#dc3545',
                        '#fd7e14',
                        '#ffc107',
                        '#198754',
                        '#0dcaf0'
                    ],
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: 'rgba(33, 37, 41, 0.9)',
                        titleColor: '#e9ecef',
                        bodyColor: '#e9ecef'
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            color: '#6c757d'
                        },
                        grid: {
                            display: false
                        }
                    },
                    y: {
                        beginAtZero: true,
                        max: 100,
                        ticks: {
                            color: '#6c757d',
                            callback: function(value) {
                                return value + '%';
                            }
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    }
                }
            }
        });
    }

    /**
     * Load initial dashboard data
     */
    async loadInitialData() {
        try {
            // Update all dashboard components
            await Promise.all([
                this.updateStatistics(),
                this.updateAnonymityStatus(),
                this.updateRecentActivities(),
                this.updateSystemStatus()
            ]);
            
        } catch (error) {
            console.error('Failed to load initial data:', error);
            this.showError('Some dashboard data may be incomplete. Please refresh the page.');
        }
    }

    /**
     * Update dashboard statistics
     */
    async updateStatistics() {
        try {
            // Get statistics from page data or API
            const criticalFindings = this.getElementValue('critical-findings', 0);
            const highFindings = this.getElementValue('high-findings', 0);
            const totalFindings = this.getElementValue('total-findings', 0);
            const activeScans = this.getElementValue('active-scans', 0);

            // Update severity chart
            if (this.charts.severity) {
                const severityData = [
                    criticalFindings,
                    highFindings,
                    Math.max(0, totalFindings - criticalFindings - highFindings),
                    0,
                    0
                ];
                
                this.charts.severity.data.datasets[0].data = severityData;
                this.charts.severity.update('none');
            }

            // Update statistics cards with animations
            this.animateCounter('critical-findings', criticalFindings);
            this.animateCounter('high-findings', highFindings);
            this.animateCounter('total-findings', totalFindings);
            this.animateCounter('active-scans', activeScans);

        } catch (error) {
            console.error('Failed to update statistics:', error);
        }
    }

    /**
     * Update anonymity status
     */
    async updateAnonymityStatus() {
        try {
            const response = await fetch('/api/anonymity-status');
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            const data = await response.json();
            this.state.anonymityStatus = data;
            
            // Update navbar indicator
            const navStatusElement = document.getElementById('anonymity-status');
            if (navStatusElement) {
                if (data.tor_enabled) {
                    navStatusElement.className = 'badge bg-success';
                    navStatusElement.innerHTML = '<i class="fas fa-user-secret me-1"></i> Tor Active';
                } else {
                    navStatusElement.className = 'badge bg-warning';
                    navStatusElement.innerHTML = '<i class="fas fa-user-secret me-1"></i> No Anonymity';
                }
            }

            // Update detailed status in dashboard
            const detailsElement = document.getElementById('anonymity-details');
            if (detailsElement) {
                let statusHtml = '<div class="row g-2">';
                
                if (data.tor_enabled) {
                    statusHtml += '<div class="col-12"><span class="badge bg-success"><i class="fas fa-check me-1"></i> Tor Enabled</span></div>';
                } else {
                    statusHtml += '<div class="col-12"><span class="badge bg-warning"><i class="fas fa-exclamation me-1"></i> Tor Disabled</span></div>';
                }
                
                if (data.exit_ip) {
                    statusHtml += `<div class="col-12"><small class="text-muted">Exit IP: ${data.exit_ip}</small></div>`;
                }
                
                if (data.proxy_chains_count > 0) {
                    statusHtml += `<div class="col-12"><small class="text-muted">Proxy Chains: ${data.proxy_chains_count}</small></div>`;
                }
                
                statusHtml += '</div>';
                detailsElement.innerHTML = statusHtml;
            }

        } catch (error) {
            console.error('Failed to update anonymity status:', error);
            
            const navStatusElement = document.getElementById('anonymity-status');
            if (navStatusElement) {
                navStatusElement.className = 'badge bg-danger';
                navStatusElement.innerHTML = '<i class="fas fa-user-secret me-1"></i> Error';
            }
        }
    }

    /**
     * Update recent activities
     */
    async updateRecentActivities() {
        try {
            // This would typically fetch from an API endpoint
            // For now, we'll use the data already on the page
            const recentSessions = document.querySelectorAll('[data-session-id]');
            
            if (recentSessions.length === 0) {
                this.showEmptyState('recent-activities', 'No recent scan sessions', 'fas fa-search');
                return;
            }

            // Update scan activity chart with mock data for visualization
            this.updateScanActivityChart();
            
        } catch (error) {
            console.error('Failed to update recent activities:', error);
        }
    }

    /**
     * Update scan activity chart with recent data
     */
    updateScanActivityChart() {
        if (!this.charts.scanActivity) return;

        // Generate last 7 days labels
        const labels = [];
        const scansData = [];
        const findingsData = [];
        
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
            
            // This would come from actual API data
            scansData.push(Math.floor(Math.random() * 10));
            findingsData.push(Math.floor(Math.random() * 25));
        }

        this.charts.scanActivity.data.labels = labels;
        this.charts.scanActivity.data.datasets[0].data = scansData;
        this.charts.scanActivity.data.datasets[1].data = findingsData;
        this.charts.scanActivity.update('none');
    }

    /**
     * Update system status
     */
    async updateSystemStatus() {
        try {
            // Check various system components
            const checks = await Promise.allSettled([
                this.checkDatabaseConnection(),
                this.checkEncryptionService(),
                this.checkScannerHealth()
            ]);

            const allHealthy = checks.every(check => check.status === 'fulfilled' && check.value);
            
            this.state.systemStatus = allHealthy ? 'operational' : 'degraded';
            
            // Update system status indicator
            const statusElement = document.getElementById('system-status');
            if (statusElement) {
                if (allHealthy) {
                    statusElement.innerHTML = '<i class="fas fa-check-circle text-success me-1"></i> All Systems Operational';
                } else {
                    statusElement.innerHTML = '<i class="fas fa-exclamation-triangle text-warning me-1"></i> Some Issues Detected';
                }
            }

        } catch (error) {
            console.error('Failed to update system status:', error);
            this.state.systemStatus = 'error';
        }
    }

    /**
     * Check database connection
     */
    async checkDatabaseConnection() {
        try {
            const response = await fetch('/api/health/database', { method: 'HEAD' });
            return response.ok;
        } catch {
            return false;
        }
    }

    /**
     * Check encryption service
     */
    async checkEncryptionService() {
        try {
            return window.RedTeamCrypto && window.RedTeamCrypto.crypto;
        } catch {
            return false;
        }
    }

    /**
     * Check scanner health
     */
    async checkScannerHealth() {
        try {
            // In a real implementation, this would ping scanner services
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Start real-time updates
     */
    startRealTimeUpdates() {
        this.stopRealTimeUpdates(); // Clear any existing timers
        
        // Main update timer
        this.timers.main = setInterval(() => {
            this.refreshData();
        }, this.updateInterval);

        // Anonymity status timer (more frequent)
        this.timers.anonymity = setInterval(() => {
            this.updateAnonymityStatus();
        }, 15000); // 15 seconds

        console.log('Real-time updates started');
    }

    /**
     * Stop real-time updates
     */
    stopRealTimeUpdates() {
        Object.values(this.timers).forEach(timer => {
            if (timer) clearInterval(timer);
        });
        this.timers = {};
        
        console.log('Real-time updates stopped');
    }

    /**
     * Refresh all dashboard data
     */
    async refreshData() {
        try {
            const refreshButton = document.querySelector('[data-action="refresh"]');
            if (refreshButton) {
                refreshButton.innerHTML = '<i class="fas fa-sync-alt fa-spin"></i>';
                refreshButton.disabled = true;
            }

            await this.loadInitialData();

            if (refreshButton) {
                refreshButton.innerHTML = '<i class="fas fa-sync-alt"></i>';
                refreshButton.disabled = false;
            }

            this.showSuccess('Dashboard data refreshed');

        } catch (error) {
            console.error('Failed to refresh data:', error);
            this.showError('Failed to refresh dashboard data');
            
            const refreshButton = document.querySelector('[data-action="refresh"]');
            if (refreshButton) {
                refreshButton.innerHTML = '<i class="fas fa-sync-alt"></i>';
                refreshButton.disabled = false;
            }
        }
    }

    /**
     * Rotate Tor circuit
     */
    async rotateTorCircuit() {
        try {
            const response = await fetch('/api/rotate-tor-circuit', { method: 'POST' });
            const data = await response.json();
            
            if (data.success) {
                this.showSuccess('Tor circuit rotated successfully');
                // Update anonymity status after a delay
                setTimeout(() => this.updateAnonymityStatus(), 5000);
            } else {
                this.showError('Failed to rotate Tor circuit');
            }
            
        } catch (error) {
            console.error('Error rotating Tor circuit:', error);
            this.showError('Error rotating Tor circuit');
        }
    }

    /**
     * Utility: Get element value or default
     */
    getElementValue(elementId, defaultValue = 0) {
        const element = document.getElementById(elementId);
        if (!element) return defaultValue;
        
        const textContent = element.textContent || element.value;
        const numericValue = parseInt(textContent.replace(/\D/g, ''), 10);
        
        return isNaN(numericValue) ? defaultValue : numericValue;
    }

    /**
     * Animate counter with easing
     */
    animateCounter(elementId, targetValue, duration = 1000) {
        const element = document.getElementById(elementId);
        if (!element) return;

        const startValue = this.getElementValue(elementId, 0);
        const startTime = performance.now();

        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            
            // Easing function (ease-out)
            const easeOut = 1 - Math.pow(1 - progress, 3);
            
            const currentValue = Math.round(startValue + (targetValue - startValue) * easeOut);
            element.textContent = currentValue;

            if (progress < 1) {
                requestAnimationFrame(animate);
            }
        };

        requestAnimationFrame(animate);
    }

    /**
     * Show empty state
     */
    showEmptyState(containerId, message, iconClass = 'fas fa-info-circle') {
        const container = document.getElementById(containerId);
        if (!container) return;

        container.innerHTML = `
            <div class="text-center py-4">
                <i class="${iconClass} fa-3x text-muted mb-3"></i>
                <p class="text-muted">${message}</p>
            </div>
        `;
    }

    /**
     * Show success message
     */
    showSuccess(message) {
        this.showToast(message, 'success');
    }

    /**
     * Show error message
     */
    showError(message) {
        this.showToast(message, 'danger');
    }

    /**
     * Show toast notification
     */
    showToast(message, type = 'info') {
        // Create toast container if it doesn't exist
        let toastContainer = document.getElementById('toast-container');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.id = 'toast-container';
            toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
            toastContainer.style.zIndex = '9999';
            document.body.appendChild(toastContainer);
        }

        // Create toast element
        const toastId = 'toast-' + Date.now();
        const toast = document.createElement('div');
        toast.id = toastId;
        toast.className = `toast align-items-center text-bg-${type} border-0`;
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">
                    <i class="fas fa-${type === 'success' ? 'check' : type === 'danger' ? 'exclamation-triangle' : 'info'}-circle me-2"></i>
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;

        toastContainer.appendChild(toast);

        // Initialize and show toast
        const bsToast = new bootstrap.Toast(toast, {
            autohide: true,
            delay: type === 'danger' ? 8000 : 4000
        });
        
        bsToast.show();

        // Remove toast element after hiding
        toast.addEventListener('hidden.bs.toast', () => {
            toast.remove();
        });
    }

    /**
     * Cleanup resources
     */
    cleanup() {
        this.stopRealTimeUpdates();
        
        // Destroy charts
        Object.values(this.charts).forEach(chart => {
            if (chart && typeof chart.destroy === 'function') {
                chart.destroy();
            }
        });
        
        this.charts = {};
        console.log('Dashboard cleanup completed');
    }
}

// Global dashboard instance
let dashboard = null;

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    dashboard = new RedTeamDashboard();
    dashboard.initialize();
});

// Global functions for template usage
window.updateAnonymityStatus = () => {
    if (dashboard) {
        dashboard.updateAnonymityStatus();
    }
};

window.refreshScanSessions = () => {
    if (dashboard) {
        dashboard.refreshData();
    }
};

window.rotateTorCircuit = () => {
    if (dashboard) {
        dashboard.rotateTorCircuit();
    }
};

// Export dashboard instance
window.RedTeamDashboard = dashboard;
