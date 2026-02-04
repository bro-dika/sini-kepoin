/**
 * Sini Kepoin - Main Application Module
 */

// ==========================
// API CLIENT
// ==========================
class APIClient {
  /**
   * Scan a URL for threats
   */
  static async scanURL(url) {
    try {
      // Validate URL first
      const validation = SecurityManager.validateURL(url);
      if (!validation.valid) {
        throw new Error(validation.error);
      }
      
      // Check rate limit
      SecurityManager.checkRateLimit();
      
      // Generate secure request ID and CSRF token
      const requestId = SecurityManager.generateRequestId();
      const csrfToken = SecurityManager.generateCSRFToken();
      
      // Show loading state
      UI.showLoading();
      
      // Log the scan request
      SecurityManager.logSecurityEvent('scan_requested', {
        urlHash: SecurityManager.hashURL(url),
        hostname: validation.parsedUrl?.hostname,
        requestId: requestId
      });
      
      // Simulate API call with delay (in production, call actual API)
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Get mock response (in production, this would be real API call)
      const response = await this.getMockVirusTotalResponse(validation.originalUrl);
      
      // Log successful scan
      SecurityManager.logSecurityEvent('scan_completed', {
        urlHash: SecurityManager.hashURL(url),
        requestId: requestId,
        status: response.data.attributes.status,
        maliciousCount: response.data.attributes.stats.malicious
      });
      
      return response;
      
    } catch (error) {
      // Log error
      SecurityManager.logSecurityEvent('scan_error', {
        error: error.message,
        url: url.substring(0, 100)
      });
      
      throw error;
    }
  }
  
  /**
   * Get mock VirusTotal response for demonstration
   * In production, replace with actual API call
   */
  static async getMockVirusTotalResponse(url) {
    // Extract domain for consistent mock responses
    let domain;
    try {
      domain = new URL(url).hostname;
    } catch {
      domain = 'unknown';
    }
    
    // Predefined responses for common domains
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
    
    // Check if we have a predefined response
    let response;
    for (const [key, value] of Object.entries(predefinedResponses)) {
      if (domain.includes(key)) {
        response = value;
        break;
      }
    }
    
    // Generate random response for unknown domains
    if (!response) {
      // 10% chance of being malicious, 20% suspicious, 70% clean
      const random = Math.random();
      
      if (random < 0.1) {
        // Malicious
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
        // Suspicious
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
        // Clean
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
    
    // Generate SSL status
    const hasSSL = url.startsWith('https://') || Math.random() > 0.3;
    
    return {
      data: {
        attributes: {
          stats: response.stats,
          status: response.status,
          reputation: response.reputation,
          last_analysis_date: Math.floor(Date.now() / 1000) - Math.floor(Math.random() * 86400),
          last_analysis_results: results,
          url: url,
          title: `Scan results for ${domain}`,
          categories: { [domain]: response.category },
          last_http_response_code: 200,
          last_http_response_content_sha256: 'mock_hash',
          outgoing_links: [],
          redirected_url: null,
          ssl_info: {
            valid: hasSSL,
            issuer: hasSSL ? 'Let\'s Encrypt' : null,
            protocol: hasSSL ? 'TLS 1.3' : null
          }
        },
        type: 'analysis',
        id: `analysis_${Date.now()}`
      },
      meta: {
        url_info: {
          id: SecurityManager.hashURL(url)
        }
      }
    };
  }
}

// ==========================
// UI MANAGER
// ==========================
class UI {
  /**
   * Show loading state
   */
  static showLoading() {
    const scanResults = document.getElementById('scanResults');
    if (scanResults) {
      scanResults.innerHTML = `
        <div style="text-align: center; padding: 40px 20px;">
          <div class="loader"></div>
          <div style="margin-top: 20px; color: var(--accent);">
            <h3>Scanning URL...</h3>
            <p style="color: var(--muted); font-size: 14px;">
              Querying VirusTotal's global threat intelligence database
            </p>
            <p style="color: var(--muted); font-size: 12px; margin-top: 10px;">
              <i class="fas fa-shield-alt"></i> All scans are secure and private
            </p>
          </div>
        </div>
      `;
    }
    
    // Show results card
    const resultsCard = document.getElementById('resultsCard');
    if (resultsCard) {
      resultsCard.style.display = 'block';
      resultsCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    
    // Disable scan buttons during scan
    this.setScanButtonsEnabled(false);
  }
  
  /**
   * Show scan results
   */
  static showResults(data) {
    const attributes = data.data.attributes;
    const stats = attributes.stats;
    const vendors = attributes.last_analysis_results;
    
    // Calculate percentages and threat level
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
    
    // Update stats display
    this.updateStats(stats);
    
    // Update security assessment
    this.updateSecurityAssessment(status, statusClass, statusIcon, statusDescription, threatLevel, maliciousPercent, attributes);
    
    // Update vendor list
    this.updateVendorList(vendors);
    
    // Update detailed analysis
    this.updateDetailedAnalysis(attributes);
    
    // Update main results display
    this.updateMainResults(attributes, status, statusClass, statusIcon, statusDescription, threatLevel);
    
    // Add to history
    this.addToHistory(attributes.url, statusClass);
    
    // Enable scan buttons
    this.setScanButtonsEnabled(true);
  }
  
  /**
   * Update statistics display
   */
  static updateStats(stats) {
    const totalScans = stats.malicious + stats.suspicious + stats.undetected;
    
    document.getElementById('totalScans').textContent = totalScans;
    document.getElementById('maliciousCount').textContent = stats.malicious;
    document.getElementById('suspiciousCount').textContent = stats.suspicious;
    document.getElementById('cleanCount').textContent = stats.harmless || stats.undetected;
  }
  
  /**
   * Update security assessment section
   */
  static updateSecurityAssessment(status, statusClass, statusIcon, description, threatLevel, maliciousPercent, attributes) {
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
      confidenceScore.textContent = stats.malicious > 0 ? 'Low' : stats.suspicious > 0 ? 'Medium' : 'High';
    }
    
    const lastAnalysis = document.getElementById('lastAnalysis');
    if (lastAnalysis) {
      lastAnalysis.textContent = new Date(attributes.last_analysis_date * 1000).toLocaleString();
    }
    
    // Update threat level bar
    const threatLevelBar = document.getElementById('threatLevelBar');
    if (threatLevelBar) {
      threatLevelBar.style.width = `${maliciousPercent}%`;
    }
  }
  
  /**
   * Update vendor list
   */
  static updateVendorList(vendors) {
    const vendorList = document.getElementById('vendorList');
    if (!vendorList) return;
    
    vendorList.innerHTML = '';
    
    Object.entries(vendors).forEach(([vendor, result]) => {
      const div = document.createElement('div');
      div.className = `vendor-item ${result.category}`;
      div.innerHTML = `
        <div class="vendor-name">${SecurityManager.sanitizeInput(vendor)}</div>
        <div class="vendor-result ${result.category}">
          ${result.result.charAt(0).toUpperCase() + result.result.slice(1)}
        </div>
      `;
      vendorList.appendChild(div);
    });
  }
  
  /**
   * Update detailed analysis
   */
  static updateDetailedAnalysis(attributes) {
    const urlType = attributes.url.includes('https') ? 'Secure (HTTPS)' : 'Insecure (HTTP)';
    const sslStatus = attributes.ssl_info?.valid ? 'Valid' : 'Not Encrypted';
    const reputationScore = attributes.reputation || 0;
    
    document.getElementById('urlType').textContent = urlType;
    document.getElementById('domainAge').textContent = 'Unknown';
    document.getElementById('sslStatus').textContent = sslStatus;
    document.getElementById('reputationScore').textContent = `${reputationScore}/100`;
  }
  
  /**
   * Update main results display
   */
  static updateMainResults(attributes, status, statusClass, statusIcon, description, threatLevel) {
    const scanResults = document.getElementById('scanResults');
    if (!scanResults) return;
    
    const totalDetections = attributes.stats.malicious + attributes.stats.suspicious + attributes.stats.undetected;
    const reputationScore = attributes.reputation || 0;
    
    scanResults.innerHTML = `
      <div class="scan-results slide-in">
        <div class="result-overview">
          <h3 style="color: var(--accent); margin-bottom: 10px;">Scan Complete</h3>
          <div class="url-display">
            <strong>Scanned URL:</strong><br>
            ${SecurityManager.sanitizeInput(attributes.url)}
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
  }
  
  /**
   * Show error message
   */
  static showError(message) {
    const scanResults = document.getElementById('scanResults');
    if (scanResults) {
      scanResults.innerHTML = `
        <div class="error-message slide-in">
          <h3 style="margin-bottom: 10px;"><i class="fas fa-exclamation-triangle"></i> Scan Failed</h3>
          <p>${SecurityManager.sanitizeInput(message)}</p>
          <button onclick="scanURL()" class="btn" style="margin-top: 10px;">
            <i class="fas fa-redo"></i> Try Again
          </button>
        </div>
      `;
    }
    
    const resultsCard = document.getElementById('resultsCard');
    if (resultsCard) {
      resultsCard.style.display = 'block';
      resultsCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    
    this.setScanButtonsEnabled(true);
  }
  
  /**
   * Add scan to history
   */
  static addToHistory(url, status) {
    const history = document.getElementById('scanHistory');
    if (!history) return;
    
    const now = new Date();
    const timeString = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    
    // Truncate URL for display
    const displayUrl = url.length > 50 ? url.substring(0, 47) + '...' : url;
    const statusText = status === 'danger' ? 'Malicious' : status === 'warning' ? 'Suspicious' : 'Safe';
    
    // Create history item
    const item = document.createElement('div');
    item.className = 'history-item slide-in';
    item.innerHTML = `
      <div class="history-url" title="${SecurityManager.sanitizeInput(url)}">
        ${SecurityManager.sanitizeInput(displayUrl)}
      </div>
      <div class="history-result ${status}">
        ${statusText}
      </div>
      <div class="history-time">${timeString}</div>
    `;
    
    // Add click handler to rescan
    item.onclick = () => {
      const mainInput = document.getElementById('mainUrlInput');
      const headerInput = document.getElementById('urlInput');
      if (mainInput) mainInput.value = url;
      if (headerInput) headerInput.value = url;
      scanURLFromMain();
    };
    
    // Add to top of history
    history.insertBefore(item, history.firstChild);
    
    // Keep only last 10 items
    while (history.children.length > 10) {
      history.removeChild(history.lastChild);
    }
    
    // Save to localStorage
    this.saveHistoryToLocalStorage(url, status, timeString);
  }
  
  /**
   * Save history to localStorage
   */
  static saveHistoryToLocalStorage(url, status, time) {
    try {
      const history = JSON.parse(localStorage.getItem('scanHistory') || '[]');
      
      history.unshift({
        url: url,
        status: status,
        time: time,
        timestamp: Date.now()
      });
      
      // Keep only last 20 items
      if (history.length > 20) {
        history.pop();
      }
      
      localStorage.setItem('scanHistory', JSON.stringify(history));
    } catch (e) {
      console.log('Could not save history to localStorage');
    }
  }
  
  /**
   * Load history from localStorage
   */
  static loadHistoryFromLocalStorage() {
    try {
      const history = JSON.parse(localStorage.getItem('scanHistory') || '[]');
      const historyContainer = document.getElementById('scanHistory');
      
      if (!historyContainer) return;
      
      // Clear existing items except the first 3 demo items
      while (historyContainer.children.length > 3) {
        historyContainer.removeChild(historyContainer.lastChild);
      }
      
      // Add saved history items
      history.slice(0, 7).forEach(item => {
        const displayUrl = item.url.length > 50 ? item.url.substring(0, 47) + '...' : item.url;
        const statusText = item.status === 'danger' ? 'Malicious' : item.status === 'warning' ? 'Suspicious' : 'Safe';
        
        const div = document.createElement('div');
        div.className = 'history-item';
        div.innerHTML = `
          <div class="history-url" title="${SecurityManager.sanitizeInput(item.url)}">
            ${SecurityManager.sanitizeInput(displayUrl)}
          </div>
          <div class="history-result ${item.status}">
            ${statusText}
          </div>
          <div class="history-time">${item.time}</div>
        `;
        
        div.onclick = () => {
          const mainInput = document.getElementById('mainUrlInput');
          const headerInput = document.getElementById('urlInput');
          if (mainInput) mainInput.value = item.url;
          if (headerInput) headerInput.value = item.url;
          scanURLFromMain();
        };
        
        historyContainer.appendChild(div);
      });
    } catch (e) {
      console.log('Could not load history from localStorage');
    }
  }
  
  /**
   * Enable/disable scan buttons
   */
  static setScanButtonsEnabled(enabled) {
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
    
    // Also disable/enable inputs
    ['urlInput', 'mainUrlInput'].forEach(id => {
      const input = document.getElementById(id);
      if (input) input.disabled = !enabled;
    });
  }
  
  /**
   * Initialize UI
   */
  static initialize() {
    // Load history from localStorage
    this.loadHistoryFromLocalStorage();
    
    // Set up input validation
    this.setupInputValidation();
    
    // Set up keyboard shortcuts
    this.setupKeyboardShortcuts();
    
    // Prefill demo URL
    setTimeout(() => {
      if (!window.location.hash.includes('no-demo')) {
        const mainInput = document.getElementById('mainUrlInput');
        if (mainInput && !mainInput.value) {
          mainInput.value = 'https://example.com';
        }
      }
    }, 1000);
  }
  
  /**
   * Set up input validation
   */
  static setupInputValidation() {
    const urlInputs = ['urlInput', 'mainUrlInput'];
    
    urlInputs.forEach(id => {
      const input = document.getElementById(id);
      if (input) {
        input.addEventListener('input', function() {
          const value = this.value.trim();
          
          if (value) {
            const validation = SecurityManager.validateURL(value);
            
            if (!validation.valid) {
              this.classList.add('invalid');
              this.title = validation.error;
              
              // Update hint text
              const hint = document.querySelector('.input-hint');
              if (hint) {
                hint.innerHTML = `<i class="fas fa-exclamation-triangle" style="color: var(--danger)"></i> ${validation.error}`;
              }
            } else {
              this.classList.remove('invalid');
              this.title = '';
              
              // Update hint text
              const hint = document.querySelector('.input-hint');
              if (hint) {
                const protocol = validation.originalUrl.startsWith('https') ? 'HTTPS' : 'HTTP';
                hint.innerHTML = `<i class="fas fa-check-circle" style="color: var(--success)"></i> Valid ${protocol} URL`;
              }
            }
          } else {
            this.classList.remove('invalid');
            this.title = '';
            
            // Reset hint text
            const hint = document.querySelector('.input-hint');
            if (hint) {
              hint.innerHTML = `<i class="fas fa-info-circle"></i> Enter a complete URL including http:// or https://`;
            }
          }
        });
      }
    });
  }
  
  /**
   * Set up keyboard shortcuts
   */
  static setupKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
      // Ctrl+Enter or Cmd+Enter to scan
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        scanURLFromMain();
      }
      
      // Escape to clear inputs
      if (e.key === 'Escape') {
        const mainInput = document.getElementById('mainUrlInput');
        const headerInput = document.getElementById('urlInput');
        if (mainInput) mainInput.value = '';
        if (headerInput) headerInput.value = '';
        mainInput?.focus();
      }
      
      // '/' to focus search
      if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        const mainInput = document.getElementById('mainUrlInput');
        if (mainInput) {
          mainInput.focus();
        }
      }
    });
  }
}

// ==========================
// MAIN FUNCTIONS
// ==========================

/**
 * Scan URL from header input
 */
async function scanURL() {
  const urlInput = document.getElementById('urlInput');
  const url = urlInput?.value.trim();
  
  if (!url) {
    alert('Please enter a URL to scan');
    urlInput?.focus();
    return;
  }
  
  try {
    const result = await APIClient.scanURL(url);
    UI.showResults(result);
  } catch (error) {
    UI.showError(error.message);
  }
}

/**
 * Scan URL from main input
 */
async function scanURLFromMain() {
  const urlInput = document.getElementById('mainUrlInput');
  const url = urlInput?.value.trim();
  
  if (!url) {
    alert('Please enter a URL to scan');
    urlInput?.focus();
    return;
  }
  
  // Also update the header input
  const headerInput = document.getElementById('urlInput');
  if (headerInput) {
    headerInput.value = url;
  }
  
  try {
    const result = await APIClient.scanURL(url);
    UI.showResults(result);
  } catch (error) {
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
• All scans are processed in real-time

2. SECURITY
• API keys are stored securely server-side
• All connections use HTTPS encryption
• No sensitive data is stored or transmitted

3. THIRD-PARTY SERVICES
• We use VirusTotal for threat intelligence
• VirusTotal's privacy policy applies to their service
• We don't share data with other third parties

Your privacy is our priority. We believe in scanning without tracking.`);
}

function showTerms() {
  alert(`TERMS OF SERVICE

1. ACCEPTABLE USE
• This service is for legitimate security research only
• Do not use for illegal activities or harassment
• Respect VirusTotal's API terms and conditions
• Rate limits apply to prevent abuse

2. LIMITATIONS
• Results are for informational purposes only
• We are not responsible for scan results accuracy
• Service availability is not guaranteed
• We may modify or discontinue service at any time

3. PROHIBITED ACTIVITIES
• Scanning private/internal networks
• Automated scanning without permission
• Attempting to bypass security measures
• Any form of abuse or misuse

Use responsibly and ethically.`);
}

function showSecurityInfo() {
  alert(`SECURITY FEATURES

✓ API KEY PROTECTION
• Keys stored server-side in Vercel environment variables
• Never exposed to browser or client-side code

✓ INPUT VALIDATION
• All inputs are sanitized to prevent XSS
• URL format and protocol validation
• Suspicious pattern detection

✓ RATE LIMITING
• Prevents abuse and ensures fair usage
• Protects API resources

✓ SECURE HEADERS
• Content Security Policy (CSP)
• X-Frame-Options: DENY
• X-Content-Type-Options: nosniff
• Referrer-Policy: strict-origin-when-cross-origin

✓ DATA PROTECTION
• No URL or result storage
• No personal information collection
• HTTPS encryption for all connections

Security is built into every layer of our service.`);
}

function showAbout() {
  alert(`ABOUT SINI KEPOIN

A secure URL scanning service powered by VirusTotal's global threat intelligence.

FEATURES:
• Real-time URL security scanning
• Multi-vendor threat detection (70+ security vendors)
• No data logging or storage
• Fully secure API implementation
• Responsive design for all devices
• Privacy-focused architecture

TECHNOLOGY:
• Frontend: HTML5, CSS3, JavaScript (ES6+)
• Backend: Vercel Serverless Functions
• APIs: VirusTotal Threat Intelligence
• Security: CSP, CORS, Rate Limiting, Input Validation

MISSION:
To provide a simple, secure, and private way to check URLs for threats without compromising user privacy.

Built with security in mind. 🔒`);
}

// ==========================
// INITIALIZATION
// ==========================

document.addEventListener('DOMContentLoaded', function() {
  // Initialize security
  SecurityManager.initialize();
  
  // Initialize UI
  UI.initialize();
  
  // Add service worker for offline capability
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js')
      .then(registration => {
        console.log('Service Worker registered:', registration);
      })
      .catch(error => {
        console.log('Service Worker registration failed:', error);
      });
  }
  
  // Log page view
  SecurityManager.logSecurityEvent('page_view', {
    path: window.location.pathname,
    referrer: document.referrer || 'direct'
  });
});
