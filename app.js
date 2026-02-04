// ==========================
// CONFIGURATION
// ==========================
const CONFIG = {
    MAX_URL_LENGTH: 2048,
    ALLOWED_PROTOCOLS: ['http:', 'https:'],
    BLACKLISTED_DOMAINS: ['localhost', '127.0.0.1', '0.0.0.0', '192.168.', '10.', '172.16.'],
    SCAN_DELAY: 1500,
    RATE_LIMIT: {
        maxRequests: 10,
        timeWindow: 60000
    }
};

// ==========================
// UTILITY FUNCTIONS
// ==========================
// Fungsi helper untuk format waktu yang konsisten
function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('id-ID', { 
        hour: '2-digit', 
        minute: '2-digit',
        hour12: false 
    });
}

function formatDateTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString('id-ID', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
}

// ==========================
// STATE MANAGEMENT
// ==========================
const AppState = {
    requestCount: 0,
    lastRequestTime: Date.now(),
    cooldownUntil: 0,
    scanHistory: [],
    
    init() {
        try {
            const saved = localStorage.getItem('siniKepoinHistory');
            if (saved) {
                this.scanHistory = JSON.parse(saved);
                // Pastikan semua entry memiliki timestamp yang valid
                this.scanHistory = this.scanHistory.map(entry => {
                    if (!entry.timestamp) {
                        // Jika tidak ada timestamp, buat yang baru berdasarkan waktu sekarang dikurangi incremental
                        entry.timestamp = Date.now() - Math.random() * 86400000; // Random dalam 24 jam terakhir
                    }
                    return entry;
                });
                this.updateHistoryUI();
            }
        } catch (e) {
            console.log('Could not load history:', e);
        }
    },
    
    saveHistory() {
        try {
            localStorage.setItem('siniKepoinHistory', JSON.stringify(this.scanHistory));
        } catch (e) {
            console.log('Could not save history:', e);
        }
    },
    
    addToHistory(url, result) {
        const timestamp = Date.now();
        const entry = {
            url: url,
            result: result,
            timestamp: timestamp,
            formattedTime: formatTime(timestamp) // Simpan format waktu yang konsisten
        };
        
        this.scanHistory.unshift(entry);
        
        if (this.scanHistory.length > 20) {
            this.scanHistory.pop();
        }
        
        this.saveHistory();
        this.updateHistoryUI();
    },
    
    updateHistoryUI() {
        const historyContainer = document.getElementById('scanHistory');
        if (!historyContainer) {
            console.error('History container not found');
            return;
        }
        
        // Clear hanya item yang ditambahkan secara dinamis (keep 3 demo items pertama)
        const children = historyContainer.children;
        while (children.length > 3) {
            historyContainer.removeChild(children[children.length - 1]);
        }
        
        // Add history items (max 7)
        this.scanHistory.slice(0, 7).forEach(entry => {
            const displayUrl = entry.url.length > 50 ? entry.url.substring(0, 47) + '...' : entry.url;
            const statusText = entry.result === 'danger' ? 'Malicious' : 
                              entry.result === 'warning' ? 'Suspicious' : 'Safe';
            
            // Gunakan formattedTime jika ada, jika tidak format dari timestamp
            const displayTime = entry.formattedTime || formatTime(entry.timestamp || Date.now());
            
            const div = document.createElement('div');
            div.className = 'history-item';
            div.innerHTML = `
                <div class="history-url" title="${this.sanitize(entry.url)}">
                    ${this.sanitize(displayUrl)}
                </div>
                <div class="history-result ${entry.result}">
                    ${statusText}
                </div>
                <div class="history-time" title="${formatDateTime(entry.timestamp || Date.now())}">
                    ${displayTime}
                </div>
            `;
            
            div.addEventListener('click', () => {
                const mainInput = document.getElementById('mainUrlInput');
                const headerInput = document.getElementById('urlInput');
                if (mainInput) mainInput.value = entry.url;
                if (headerInput) headerInput.value = entry.url;
                scanURLFromMain();
            });
            
            historyContainer.appendChild(div);
        });
    },
    
    checkRateLimit() {
        const now = Date.now();
        
        // Check cooldown
        if (now < this.cooldownUntil) {
            const remaining = Math.ceil((this.cooldownUntil - now) / 1000);
            throw new Error(`Please wait ${remaining} seconds before scanning again`);
        }
        
        // Check rate limit window
        const timeDiff = now - this.lastRequestTime;
        
        if (timeDiff > CONFIG.RATE_LIMIT.timeWindow) {
            this.requestCount = 0;
            this.lastRequestTime = now;
        }
        
        if (this.requestCount >= CONFIG.RATE_LIMIT.maxRequests) {
            const waitTime = Math.ceil((CONFIG.RATE_LIMIT.timeWindow - timeDiff) / 1000);
            throw new Error(`Rate limit exceeded. Please wait ${waitTime} seconds`);
        }
        
        this.requestCount++;
        this.cooldownUntil = now + 5000;
        return true;
    },
    
    sanitize(input) {
        if (input === null || input === undefined) return '';
        if (typeof input !== 'string') input = String(input);
        
        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
    }
};

// ==========================
// URL VALIDATION
// ==========================
function validateURL(url) {
    try {
        url = url.trim();
        if (!url) {
            return { valid: false, error: 'Please enter a URL' };
        }
        
        if (url.length > CONFIG.MAX_URL_LENGTH) {
            return { valid: false, error: 'URL is too long (max 2048 characters)' };
        }
        
        let urlToParse = url;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            urlToParse = 'https://' + url;
        }
        
        const parsedUrl = new URL(urlToParse);
        
        if (!CONFIG.ALLOWED_PROTOCOLS.includes(parsedUrl.protocol)) {
            return { valid: false, error: 'Only HTTP and HTTPS URLs are allowed' };
        }
        
        const hostname = parsedUrl.hostname.toLowerCase();
        for (const blacklisted of CONFIG.BLACKLISTED_DOMAINS) {
            if (hostname.includes(blacklisted)) {
                return { valid: false, error: 'Private/internal domains cannot be scanned' };
            }
        }
        
        const suspiciousPatterns = [
            /\.exe$/i, /\.js$/i, /\.vbs$/i, /\.jar$/i,
            /\.bat$/i, /\.cmd$/i, /\.scr$/i, /\.pif$/i,
            /data:/i, /javascript:/i, /vbscript:/i
        ];
        
        for (const pattern of suspiciousPatterns) {
            if (pattern.test(url)) {
                return { valid: false, error: 'URL contains suspicious patterns' };
            }
        }
        
        return { 
            valid: true, 
            parsedUrl: parsedUrl,
            originalUrl: url.includes('://') ? url : `https://${url}`
        };
        
    } catch (error) {
        return { 
            valid: false, 
            error: 'Invalid URL format. Please include http:// or https://' 
        };
    }
}

// ==========================
// MOCK VIRUSTOTAL RESPONSE
// ==========================
function getMockVirusTotalResponse(url) {
    let domain = 'unknown';
    try {
        domain = new URL(url).hostname;
    } catch (e) {
        domain = url.replace(/^https?:\/\//, '').split('/')[0];
    }
    
    // Predefined responses
    const predefinedResponses = {
        'google.com': {
            stats: { malicious: 0, suspicious: 0, undetected: 72, harmless: 70 },
            status: 'clean',
            reputation: 95,
            category: 'search_engine'
        },
        'example.com': {
            stats: { malicious: 0, suspicious: 0, undetected: 65, harmless: 65 },
            status: 'clean',
            reputation: 85,
            category: 'education'
        },
        'github.com': {
            stats: { malicious: 0, suspicious: 0, undetected: 70, harmless: 68 },
            status: 'clean',
            reputation: 90,
            category: 'technology'
        },
        'malware.test.com': {
            stats: { malicious: 42, suspicious: 8, undetected: 22, harmless: 0 },
            status: 'malicious',
            reputation: 10,
            category: 'malicious'
        },
        'phishing.test.com': {
            stats: { malicious: 35, suspicious: 12, undetected: 25, harmless: 0 },
            status: 'malicious',
            reputation: 15,
            category: 'phishing'
        },
        'suspicious.test.com': {
            stats: { malicious: 5, suspicious: 15, undetected: 52, harmless: 30 },
            status: 'suspicious',
            reputation: 45,
            category: 'suspicious'
        }
    };
    
    let response;
    for (const [key, value] of Object.entries(predefinedResponses)) {
        if (domain.includes(key)) {
            response = value;
            break;
        }
    }
    
    if (!response) {
        const random = Math.random();
        
        if (random < 0.1) {
            const malicious = Math.floor(Math.random() * 30) + 10;
            const suspicious = Math.floor(Math.random() * 10) + 5;
            const undetected = 72 - malicious - suspicious;
            const harmless = Math.floor(Math.random() * (undetected - 10));
            
            response = {
                stats: { malicious, suspicious, undetected, harmless },
                status: 'malicious',
                reputation: Math.floor(Math.random() * 30) + 5,
                category: 'malicious'
            };
        } else if (random < 0.3) {
            const malicious = Math.floor(Math.random() * 5);
            const suspicious = Math.floor(Math.random() * 20) + 5;
            const undetected = 72 - malicious - suspicious;
            const harmless = Math.floor(Math.random() * (undetected - 20));
            
            response = {
                stats: { malicious, suspicious, undetected, harmless },
                status: 'suspicious',
                reputation: Math.floor(Math.random() * 40) + 30,
                category: 'suspicious'
            };
        } else {
            const malicious = 0;
            const suspicious = Math.random() < 0.2 ? Math.floor(Math.random() * 5) : 0;
            const undetected = 72 - malicious - suspicious;
            const harmless = Math.floor(Math.random() * (undetected - 5)) + 5;
            
            response = {
                stats: { malicious, suspicious, undetected, harmless },
                status: 'clean',
                reputation: Math.floor(Math.random() * 30) + 70,
                category: 'unknown'
            };
        }
    }
    
    // Generate vendor results
    const vendors = [
        { name: 'Google Safe Browsing', weight: 0.9 },
        { name: 'Norton Safe Web', weight: 0.8 },
        { name: 'McAfee', weight: 0.85 },
        { name: 'ESET', weight: 0.75 },
        { name: 'Bitdefender', weight: 0.8 },
        { name: 'Kaspersky', weight: 0.85 },
        { name: 'Trend Micro', weight: 0.7 },
        { name: 'Sophos', weight: 0.75 },
        { name: 'Avira', weight: 0.7 },
        { name: 'Avast', weight: 0.8 },
        { name: 'Malwarebytes', weight: 0.85 },
        { name: 'Comodo', weight: 0.6 }
    ];
    
    const results = {};
    vendors.forEach(vendor => {
        const rand = Math.random();
        const adjustedWeight = vendor.weight;
        
        if (response.stats.malicious > 0 && rand < adjustedWeight * 0.7) {
            results[vendor.name] = { category: 'malicious', result: 'malicious' };
        } else if (response.stats.suspicious > 0 && rand < adjustedWeight * 0.5) {
            results[vendor.name] = { category: 'suspicious', result: 'suspicious' };
        } else {
            results[vendor.name] = { category: 'harmless', result: 'clean' };
        }
    });
    
    const currentTimestamp = Date.now();
    
    return {
        data: {
            attributes: {
                stats: response.stats,
                status: response.status,
                reputation: response.reputation,
                last_analysis_date: Math.floor(currentTimestamp / 1000) - Math.floor(Math.random() * 86400),
                last_analysis_results: results,
                url: url,
                title: `Scan results for ${domain}`,
                categories: { [domain]: response.category },
                ssl_info: {
                    valid: url.startsWith('https://') || Math.random() > 0.3
                },
                scan_timestamp: currentTimestamp // Tambahkan timestamp scan
            }
        }
    };
}

// ==========================
// UI FUNCTIONS
// ==========================
const UI = {
    showLoading() {
        const scanResults = document.getElementById('scanResults');
        if (scanResults) {
            scanResults.innerHTML = `
                <div style="text-align: center; padding: 40px 20px;">
                    <div class="loader"></div>
                    <div style="margin-top: 20px; color: var(--accent);">
                        <h3>Scanning URL...</h3>
                        <p style="color: var(--muted); font-size: 14px;">
                            Analyzing security threats and vulnerabilities
                        </p>
                    </div>
                </div>
            `;
        }
        
        const resultsCard = document.getElementById('resultsCard');
        if (resultsCard) {
            resultsCard.style.display = 'block';
            setTimeout(() => {
                resultsCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }, 100);
        }
        
        this.setButtonsEnabled(false);
    },
    
    showResults(data) {
        try {
            const attributes = data.data.attributes;
            const stats = attributes.stats;
            const vendors = attributes.last_analysis_results;
            
            // Calculate threat level
            const totalDetections = stats.malicious + stats.suspicious + stats.undetected;
            const maliciousPercent = totalDetections > 0 ? (stats.malicious / totalDetections * 100).toFixed(1) : 0;
            const threatLevel = maliciousPercent > 20 ? 'High' : maliciousPercent > 5 ? 'Medium' : 'Low';
            
            // Determine status
            let status, statusClass, statusIcon, statusDescription;
            if (stats.malicious > 0) {
                status = 'Malicious Threat';
                statusClass = 'danger';
                statusIcon = 'fa-skull-crossbones';
                statusDescription = `${stats.malicious} security vendors flagged this URL as malicious`;
            } else if (stats.suspicious > 0) {
                status = 'Suspicious Activity';
                statusClass = 'warning';
                statusIcon = 'fa-exclamation-triangle';
                statusDescription = `${stats.suspicious} vendors detected suspicious behavior`;
            } else {
                status = 'Safe to Visit';
                statusClass = 'safe';
                statusIcon = 'fa-check-circle';
                statusDescription = 'No security vendors detected threats';
            }
            
            // Update all UI components
            this.updateStats(stats);
            this.updateSecurityAssessment(status, statusClass, statusIcon, statusDescription, threatLevel, maliciousPercent, attributes);
            this.updateVendorList(vendors);
            this.updateDetailedAnalysis(attributes);
            this.updateMainResults(attributes, status, statusClass, statusIcon, statusDescription, threatLevel);
            
            // Add to history
            AppState.addToHistory(attributes.url, statusClass);
            
            // Enable buttons
            this.setButtonsEnabled(true);
            
        } catch (error) {
            console.error('Error showing results:', error);
            this.showError('Failed to display scan results. Please try again.');
        }
    },
    
    updateStats(stats) {
        try {
            const totalScans = stats.malicious + stats.suspicious + stats.undetected;
            
            const totalScansEl = document.getElementById('totalScans');
            const maliciousCountEl = document.getElementById('maliciousCount');
            const suspiciousCountEl = document.getElementById('suspiciousCount');
            const cleanCountEl = document.getElementById('cleanCount');
            
            if (totalScansEl) totalScansEl.textContent = totalScans;
            if (maliciousCountEl) maliciousCountEl.textContent = stats.malicious;
            if (suspiciousCountEl) suspiciousCountEl.textContent = stats.suspicious;
            if (cleanCountEl) cleanCountEl.textContent = stats.harmless || stats.undetected;
        } catch (error) {
            console.error('Error updating stats:', error);
        }
    },
    
    updateSecurityAssessment(status, statusClass, statusIcon, description, threatLevel, maliciousPercent, attributes) {
        try {
            const statusIconElement = document.getElementById('statusIcon');
            if (statusIconElement) {
                statusIconElement.className = `status-icon ${statusClass}`;
                statusIconElement.innerHTML = `<i class="fas ${statusIcon}"></i>`;
            }
            
            const statusTitle = document.getElementById('statusTitle');
            if (statusTitle) {
                statusTitle.textContent = status;
                statusTitle.className = statusClass;
            }
            
            const statusDescription = document.getElementById('statusDescription');
            if (statusDescription) {
                statusDescription.textContent = description;
            }
            
            const threatLevelElement = document.getElementById('threatLevel');
            if (threatLevelElement) {
                threatLevelElement.textContent = threatLevel;
                threatLevelElement.className = statusClass;
            }
            
            const confidenceScore = document.getElementById('confidenceScore');
            if (confidenceScore) {
                confidenceScore.textContent = attributes.stats.malicious > 0 ? 'Low' : 
                                            attributes.stats.suspicious > 0 ? 'Medium' : 'High';
            }
            
            const lastAnalysis = document.getElementById('lastAnalysis');
            if (lastAnalysis) {
                // Gunakan timestamp dari scan jika ada, jika tidak gunakan last_analysis_date
                const timestamp = attributes.scan_timestamp || (attributes.last_analysis_date * 1000);
                lastAnalysis.textContent = formatDateTime(timestamp);
            }
            
            const threatLevelBar = document.getElementById('threatLevelBar');
            if (threatLevelBar) {
                threatLevelBar.style.width = `${maliciousPercent}%`;
            }
        } catch (error) {
            console.error('Error updating security assessment:', error);
        }
    },
    
    updateVendorList(vendors) {
        try {
            const vendorList = document.getElementById('vendorList');
            if (!vendorList) {
                console.error('Vendor list element not found');
                return;
            }
            
            vendorList.innerHTML = '';
            
            Object.entries(vendors).forEach(([vendor, result]) => {
                const div = document.createElement('div');
                div.className = `vendor-item ${result.category}`;
                div.innerHTML = `
                    <div class="vendor-name">${AppState.sanitize(vendor)}</div>
                    <div class="vendor-result ${result.category}">
                        ${result.result.charAt(0).toUpperCase() + result.result.slice(1)}
                    </div>
                `;
                vendorList.appendChild(div);
            });
            
            console.log(`Updated vendor list with ${Object.keys(vendors).length} vendors`);
        } catch (error) {
            console.error('Error updating vendor list:', error);
        }
    },
    
    updateDetailedAnalysis(attributes) {
        try {
            const urlType = attributes.url.includes('https') ? 'Secure (HTTPS)' : 'Insecure (HTTP)';
            const sslStatus = attributes.ssl_info?.valid ? 'Valid' : 'Not Encrypted';
            const reputationScore = attributes.reputation || 0;
            
            const urlTypeEl = document.getElementById('urlType');
            const domainAgeEl = document.getElementById('domainAge');
            const sslStatusEl = document.getElementById('sslStatus');
            const reputationScoreEl = document.getElementById('reputationScore');
            
            if (urlTypeEl) urlTypeEl.textContent = urlType;
            if (domainAgeEl) domainAgeEl.textContent = 'Unknown';
            if (sslStatusEl) sslStatusEl.textContent = sslStatus;
            if (reputationScoreEl) reputationScoreEl.textContent = `${reputationScore}/100`;
            
            // Update scan time jika ada elemen untuk itu
            const scanTimeEl = document.getElementById('scanTime');
            if (scanTimeEl && attributes.scan_timestamp) {
                scanTimeEl.textContent = formatDateTime(attributes.scan_timestamp);
            }
        } catch (error) {
            console.error('Error updating detailed analysis:', error);
        }
    },
    
    updateMainResults(attributes, status, statusClass, statusIcon, description, threatLevel) {
        try {
            const scanResults = document.getElementById('scanResults');
            if (!scanResults) {
                console.error('Scan results element not found');
                return;
            }
            
            const totalDetections = attributes.stats.malicious + attributes.stats.suspicious + attributes.stats.undetected;
            const reputationScore = attributes.reputation || 0;
            const scanTime = attributes.scan_timestamp ? formatDateTime(attributes.scan_timestamp) : 'Just now';
            
            scanResults.innerHTML = `
                <div class="scan-results">
                    <div class="result-overview">
                        <h3 style="color: var(--accent); margin-bottom: 10px;">Scan Complete</h3>
                        <div class="scan-time" style="font-size: 12px; color: var(--muted); margin-bottom: 10px;">
                            <i class="fas fa-clock"></i> Scanned at: ${scanTime}
                        </div>
                        <div class="url-display">
                            <strong>Scanned URL:</strong><br>
                            ${AppState.sanitize(attributes.url)}
                        </div>
                        
                        <div class="security-status">
                            <div class="status-icon ${statusClass}">
                                <i class="fas ${statusIcon}"></i>
                            </div>
                            <div class="status-details">
                                <div class="status-title ${statusClass}">${status}</div>
                                <div class="status-description">${description}</div>
                            </div>
                        </div>
                        
                        <div style="margin-top: 20px;">
                            <div class="badge ${statusClass}">${status}</div>
                            <div class="badge">${totalDetections} Vendors Checked</div>
                            <div class="badge">Threat Level: ${threatLevel}</div>
                            <div class="badge">Reputation: ${reputationScore}/100</div>
                            ${attributes.ssl_info?.valid ? '<div class="badge safe">SSL Secured</div>' : ''}
                        </div>
                    </div>
                </div>
            `;
        } catch (error) {
            console.error('Error updating main results:', error);
        }
    },
    
    showError(message) {
        try {
            const scanResults = document.getElementById('scanResults');
            if (scanResults) {
                const errorTime = formatDateTime(Date.now());
                scanResults.innerHTML = `
                    <div class="error-message">
                        <h3 style="margin-bottom: 10px;"><i class="fas fa-exclamation-triangle"></i> Scan Failed</h3>
                        <p>${AppState.sanitize(message)}</p>
                        <div style="font-size: 12px; color: var(--muted); margin-top: 10px;">
                            <i class="fas fa-clock"></i> Error occurred at: ${errorTime}
                        </div>
                        <button onclick="scanURL()" class="btn" style="margin-top: 10px;">
                            <i class="fas fa-redo"></i> Try Again
                        </button>
                    </div>
                `;
            }
            
            const resultsCard = document.getElementById('resultsCard');
            if (resultsCard) {
                resultsCard.style.display = 'block';
                setTimeout(() => {
                    resultsCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }, 100);
            }
            
            this.setButtonsEnabled(true);
        } catch (error) {
            console.error('Error showing error:', error);
        }
    },
    
    setButtonsEnabled(enabled) {
        try {
            const buttons = ['scanButton', 'mainScanButton'];
            
            buttons.forEach(id => {
                const button = document.getElementById(id);
                if (button) {
                    button.disabled = !enabled;
                    
                    if (enabled) {
                        button.innerHTML = id === 'mainScanButton' 
                            ? `<i class="fas fa-shield-alt"></i><span>Scan for Threats</span>`
                            : `<i class="fas fa-search"></i><span>SCAN URL</span>`;
                    } else {
                        button.innerHTML = `<i class="fas fa-spinner fa-spin"></i><span>SCANNING...</span>`;
                    }
                }
            });
            
            ['urlInput', 'mainUrlInput'].forEach(id => {
                const input = document.getElementById(id);
                if (input) input.disabled = !enabled;
            });
        } catch (error) {
            console.error('Error setting buttons:', error);
        }
    },
    
    setupInputValidation() {
        try {
            const urlInputs = ['urlInput', 'mainUrlInput'];
            
            urlInputs.forEach(id => {
                const input = document.getElementById(id);
                if (input) {
                    input.addEventListener('input', function() {
                        const value = this.value.trim();
                        
                        if (value) {
                            const validation = validateURL(value);
                            
                            if (!validation.valid) {
                                this.classList.add('invalid');
                                this.title = validation.error;
                                
                                const hint = document.querySelector('.input-hint');
                                if (hint) {
                                    hint.innerHTML = `<i class="fas fa-exclamation-triangle" style="color: var(--danger)"></i> ${validation.error}`;
                                }
                            } else {
                                this.classList.remove('invalid');
                                this.title = '';
                                
                                const hint = document.querySelector('.input-hint');
                                if (hint) {
                                    const protocol = validation.originalUrl.startsWith('https') ? 'HTTPS' : 'HTTP';
                                    hint.innerHTML = `<i class="fas fa-check-circle" style="color: var(--success)"></i> Valid ${protocol} URL`;
                                }
                            }
                        } else {
                            this.classList.remove('invalid');
                            this.title = '';
                            
                            const hint = document.querySelector('.input-hint');
                            if (hint) {
                                hint.innerHTML = `<i class="fas fa-info-circle"></i> Enter a complete URL including http:// or https://`;
                            }
                        }
                    });
                }
            });
        } catch (error) {
            console.error('Error setting up input validation:', error);
        }
    },
    
    setupEventListeners() {
        try {
            // Setup scan buttons
            const scanButton = document.getElementById('scanButton');
            if (scanButton) {
                scanButton.addEventListener('click', scanURL);
            }
            
            const mainScanButton = document.getElementById('mainScanButton');
            if (mainScanButton) {
                mainScanButton.addEventListener('click', scanURLFromMain);
            }
            
            // Setup enter key for inputs
            const inputs = ['urlInput', 'mainUrlInput'];
            inputs.forEach(id => {
                const input = document.getElementById(id);
                if (input) {
                    input.addEventListener('keypress', function(e) {
                        if (e.key === 'Enter') {
                            if (id === 'mainUrlInput') {
                                scanURLFromMain();
                            } else {
                                scanURL();
                            }
                        }
                    });
                }
            });
            
            // Setup keyboard shortcuts
            document.addEventListener('keydown', function(e) {
                if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                    e.preventDefault();
                    scanURLFromMain();
                }
                
                if (e.key === 'Escape') {
                    const mainInput = document.getElementById('mainUrlInput');
                    const headerInput = document.getElementById('urlInput');
                    if (mainInput) mainInput.value = '';
                    if (headerInput) headerInput.value = '';
                    mainInput?.focus();
                }
                
                if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey) {
                    e.preventDefault();
                    const mainInput = document.getElementById('mainUrlInput');
                    if (mainInput) {
                        mainInput.focus();
                    }
                }
            });
            
            console.log('Event listeners setup complete');
        } catch (error) {
            console.error('Error setting up event listeners:', error);
        }
    }
};

// ==========================
// MAIN SCAN FUNCTIONS
// ==========================
async function scanURL() {
    try {
        const urlInput = document.getElementById('urlInput');
        const url = urlInput?.value.trim();
        
        if (!url) {
            alert('Please enter a URL to scan');
            urlInput?.focus();
            return;
        }
        
        const validation = validateURL(url);
        if (!validation.valid) {
            throw new Error(validation.error);
        }
        
        AppState.checkRateLimit();
        UI.showLoading();
        
        await new Promise(resolve => setTimeout(resolve, CONFIG.SCAN_DELAY));
        
        const result = getMockVirusTotalResponse(validation.originalUrl);
        UI.showResults(result);
        
    } catch (error) {
        console.error('Scan error:', error);
        UI.showError(error.message);
    }
}

async function scanURLFromMain() {
    try {
        const urlInput = document.getElementById('mainUrlInput');
        const url = urlInput?.value.trim();
        
        if (!url) {
            alert('Please enter a URL to scan');
            urlInput?.focus();
            return;
        }
        
        const headerInput = document.getElementById('urlInput');
        if (headerInput) {
            headerInput.value = url;
        }
        
        const validation = validateURL(url);
        if (!validation.valid) {
            throw new Error(validation.error);
        }
        
        AppState.checkRateLimit();
        UI.showLoading();
        
        await new Promise(resolve => setTimeout(resolve, CONFIG.SCAN_DELAY));
        
        const result = getMockVirusTotalResponse(validation.originalUrl);
        UI.showResults(result);
        
    } catch (error) {
        console.error('Scan error:', error);
        UI.showError(error.message);
    }
}

// ==========================
// MODAL FUNCTIONS
// ==========================
function showPrivacyPolicy() {
    alert(`PRIVACY POLICY

1. DATA COLLECTION
• We do NOT store any URLs you scan
• We do NOT log your IP address or personal information
• We do NOT use cookies for tracking

2. SECURITY
• All scans are processed in real-time
• No sensitive data is stored or transmitted

3. THIRD-PARTY SERVICES
• This demo uses simulated VirusTotal responses
• No actual API calls are made

Your privacy is important to us.`);
}

function showTerms() {
    alert(`TERMS OF SERVICE

1. ACCEPTABLE USE
• This is a demonstration tool for educational purposes
• Do not use for illegal activities
• Respect rate limits

2. LIMITATIONS
• Results are simulated and for demonstration only
• Service availability is not guaranteed

Use responsibly.`);
}

function showSecurityInfo() {
    alert(`SECURITY FEATURES

✓ INPUT VALIDATION
• All inputs are sanitized to prevent XSS
• URL format and protocol validation

✓ RATE LIMITING
• Prevents abuse and ensures fair usage

✓ SECURE DESIGN
• No data storage or logging
• Client-side processing only

This is a demonstration tool.`);
}

function showAbout() {
    alert(`ABOUT SINI KEPOIN

A URL security scanner demonstration tool.

FEATURES:
• Simulated URL security scanning
• Mock threat detection results
• No data logging or storage
• Responsive design for all devices

TECHNOLOGY:
• HTML5, CSS3, JavaScript
• No backend required
• Pure client-side application

This is a demonstration tool. 🔒`);
}

// ==========================
// INITIALIZATION
// ==========================
function initApp() {
    console.log('Initializing Sini Kepoin...');
    
    try {
        // Initialize app state
        AppState.init();
        
        // Setup UI
        UI.setupInputValidation();
        UI.setupEventListeners();
        
        // Setup demo history items dengan timestamp yang konsisten
        const demoItems = document.querySelectorAll('.history-item');
        const now = Date.now();
        
        demoItems.forEach((item, index) => {
            // Set timestamp untuk demo items (waktu sekarang dikurangi menit yang berbeda)
            const demoTime = now - (index * 60000); // 1 menit berbeda untuk setiap item
            const timeElement = item.querySelector('.history-time');
            if (timeElement) {
                timeElement.textContent = formatTime(demoTime);
                timeElement.title = formatDateTime(demoTime);
            }
            
            item.addEventListener('click', function() {
                const url = this.querySelector('.history-url').textContent;
                const mainInput = document.getElementById('mainUrlInput');
                const headerInput = document.getElementById('urlInput');
                if (mainInput) mainInput.value = url;
                if (headerInput) headerInput.value = url;
                scanURLFromMain();
            });
        });
        
        // Prefill demo URL
        setTimeout(() => {
            const mainInput = document.getElementById('mainUrlInput');
            if (mainInput && !mainInput.value) {
                mainInput.value = 'https://example.com';
            }
            
            // Update waktu di footer
            const footerTime = document.getElementById('currentTime');
            if (footerTime) {
                footerTime.textContent = formatDateTime(Date.now());
                // Update waktu setiap menit
                setInterval(() => {
                    footerTime.textContent = formatDateTime(Date.now());
                }, 60000);
            }
        }, 500);
        
        console.log('App initialization complete');
        
    } catch (error) {
        console.error('App initialization error:', error);
        alert('Failed to initialize application. Please refresh the page.');
    }
}

// Start the app when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
} else {
    initApp();
}

// Make functions available globally
window.scanURL = scanURL;
window.scanURLFromMain = scanURLFromMain;
window.showPrivacyPolicy = showPrivacyPolicy;
window.showTerms = showTerms;
window.showSecurityInfo = showSecurityInfo;
window.showAbout = showAbout;
window.formatTime = formatTime;
window.formatDateTime = formatDateTime;
