/**
 * Sini Kepoin - Security Module
 * Handles all security-related functionality
 */

// ==========================
// SECURITY CONFIGURATION
// ==========================
const SECURITY_CONFIG = {
  // API endpoints (point to your Vercel serverless functions)
  API_BASE_URL: 'https://api.sini-kepoin.vercel.app',
  ENDPOINTS: {
    SCAN_URL: '/api/scan',
    REPORT: '/api/report',
    ANALYZE: '/api/analyze'
  },
  
  // Rate limiting
  RATE_LIMIT: {
    enabled: true,
    maxRequests: 10,
    timeWindow: 60000, // 1 minute
    cooldown: 5000 // 5 seconds between requests
  },
  
  // Input validation
  VALIDATION: {
    maxUrlLength: 2048,
    allowedProtocols: ['http:', 'https:'],
    blacklistedDomains: ['localhost', '127.0.0.1', '0.0.0.0', '192.168.', '10.', '172.16.'],
    suspiciousPatterns: [
      /\.exe$/i,
      /\.js$/i,
      /\.vbs$/i,
      /\.jar$/i,
      /\.bat$/i,
      /\.cmd$/i,
      /\.scr$/i,
      /\.pif$/i,
      /\.com$/i,
      /data:/i,
      /javascript:/i,
      /vbscript:/i
    ]
  }
};

// ==========================
// SECURITY MANAGER CLASS
// ==========================
class SecurityManager {
  static requestCount = 0;
  static lastRequestTime = Date.now();
  static cooldownUntil = 0;
  static csrfTokens = new Set();
  
  /**
   * Sanitize input to prevent XSS attacks
   */
  static sanitizeInput(input) {
    if (input === null || input === undefined) return '';
    
    if (typeof input !== 'string') {
      input = String(input);
    }
    
    // Create a temporary div element
    const div = document.createElement('div');
    // Set text content (this automatically escapes HTML)
    div.textContent = input;
    // Return the sanitized text
    return div.innerHTML;
  }
  
  /**
   * Validate URL format and security
   */
  static validateURL(url) {
    try {
      // Trim and basic validation
      url = url.trim();
      if (!url) {
        return { valid: false, error: 'Please enter a URL' };
      }
      
      // Basic length check
      if (url.length > SECURITY_CONFIG.VALIDATION.maxUrlLength) {
        return { valid: false, error: 'URL is too long (max 2048 characters)' };
      }
      
      // Add protocol if missing (but only for display purposes)
      let urlToParse = url;
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        urlToParse = 'https://' + url;
      }
      
      // Parse URL
      const parsedUrl = new URL(urlToParse);
      
      // Protocol validation
      if (!SECURITY_CONFIG.VALIDATION.allowedProtocols.includes(parsedUrl.protocol)) {
        return { valid: false, error: 'Only HTTP and HTTPS URLs are allowed' };
      }
      
      // Domain blacklist check
      const hostname = parsedUrl.hostname.toLowerCase();
      for (const blacklisted of SECURITY_CONFIG.VALIDATION.blacklistedDomains) {
        if (hostname.includes(blacklisted)) {
          return { valid: false, error: 'Private/internal domains cannot be scanned' };
        }
      }
      
      // Check for suspicious patterns in full URL
      for (const pattern of SECURITY_CONFIG.VALIDATION.suspiciousPatterns) {
        if (pattern.test(url)) {
          return { valid: false, error: 'URL contains suspicious patterns' };
        }
      }
      
      // Check for invalid characters or patterns
      if (hostname.includes('@') || hostname.includes('..')) {
        return { valid: false, error: 'Invalid URL format' };
      }
      
      // Check for extremely short domains (potential typosquatting)
      const domainParts = hostname.split('.');
      if (domainParts.length >= 2) {
        const mainDomain = domainParts[domainParts.length - 2];
        if (mainDomain.length < 2) {
          return { valid: false, error: 'Suspicious domain name' };
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
        error: 'Invalid URL format. Please include http:// or https:// or enter a valid domain name' 
      };
    }
  }
  
  /**
   * Check and enforce rate limiting
   */
  static checkRateLimit() {
    const now = Date.now();
    
    // Check cooldown
    if (now < this.cooldownUntil) {
      const remaining = Math.ceil((this.cooldownUntil - now) / 1000);
      throw new Error(`Please wait ${remaining} seconds before scanning again`);
    }
    
    // Check rate limit window
    if (SECURITY_CONFIG.RATE_LIMIT.enabled) {
      const timeDiff = now - this.lastRequestTime;
      
      if (timeDiff > SECURITY_CONFIG.RATE_LIMIT.timeWindow) {
        // Reset if outside time window
        this.requestCount = 0;
        this.lastRequestTime = now;
      }
      
      if (this.requestCount >= SECURITY_CONFIG.RATE_LIMIT.maxRequests) {
        const waitTime = Math.ceil((SECURITY_CONFIG.RATE_LIMIT.timeWindow - timeDiff) / 1000);
        throw new Error(`Rate limit exceeded. Please wait ${waitTime} seconds`);
      }
      
      this.requestCount++;
    }
    
    // Apply cooldown
    this.cooldownUntil = now + SECURITY_CONFIG.RATE_LIMIT.cooldown;
    return true;
  }
  
  /**
   * Generate a secure request ID
   */
  static generateRequestId() {
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(2, 15);
    const hash = this.hashString(`${timestamp}_${random}_${navigator.userAgent}`);
    return `req_${timestamp}_${hash.substring(0, 8)}`;
  }
  
  /**
   * Generate CSRF token
   */
  static generateCSRFToken() {
    const token = `csrf_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
    this.csrfTokens.add(token);
    
    // Clean up old tokens (older than 1 hour)
    const oneHourAgo = Date.now() - 3600000;
    this.csrfTokens.forEach(t => {
      const parts = t.split('_');
      const timestamp = parseInt(parts[1]);
      if (timestamp < oneHourAgo) {
        this.csrfTokens.delete(t);
      }
    });
    
    return token;
  }
  
  /**
   * Validate CSRF token
   */
  static validateCSRFToken(token) {
    if (!token || !this.csrfTokens.has(token)) {
      return false;
    }
    
    // Check if token is expired (1 hour)
    const parts = token.split('_');
    if (parts.length !== 3) return false;
    
    const timestamp = parseInt(parts[1]);
    const oneHourAgo = Date.now() - 3600000;
    
    if (timestamp < oneHourAgo) {
      this.csrfTokens.delete(token);
      return false;
    }
    
    return true;
  }
  
  /**
   * Hash string for integrity checking
   */
  static hashString(str) {
    // Simple hash for demonstration
    // In production, use a proper cryptographic hash
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(36);
  }
  
  /**
   * Hash URL for storage
   */
  static hashURL(url) {
    return this.hashString(url.toLowerCase().trim());
  }
  
  /**
   * Log security event (in production, send to monitoring service)
   */
  static logSecurityEvent(event, details = {}) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event: event,
      details: details,
      userAgent: navigator.userAgent,
      url: window.location.href
    };
    
    // Log to console in development
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
      console.log('Security Event:', logEntry);
    }
    
    // In production, this would send to a monitoring service
    // Example: fetch('/api/log', { method: 'POST', body: JSON.stringify(logEntry) });
  }
  
  /**
   * Initialize security features
   */
  static initialize() {
    // Add CSP header dynamically
    const metaCSP = document.createElement('meta');
    metaCSP.httpEquiv = "Content-Security-Policy";
    metaCSP.content = "default-src 'self'; script-src 'self' 'unsafe-inline' https://kit.fontawesome.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' https://api.sini-kepoin.vercel.app;";
    document.head.appendChild(metaCSP);
    
    // Generate initial CSRF token
    const csrfToken = this.generateCSRFToken();
    document.cookie = `csrf_token=${csrfToken}; SameSite=Strict; Max-Age=3600; path=/`;
    
    // Log initialization
    this.logSecurityEvent('security_initialized', {
      hasCookies: navigator.cookieEnabled,
      hasStorage: typeof localStorage !== 'undefined',
      hasSessionStorage: typeof sessionStorage !== 'undefined'
    });
    
    return csrfToken;
  }
}
