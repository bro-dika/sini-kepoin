// api/report.js - Vercel Serverless Function for Report Generation
const crypto = require('crypto');

// In-memory cache for demonstration
// In production, use Redis or database
const reportCache = new Map();

module.exports = async (req, res) => {
  // ================= SECURITY HEADERS =================
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  
  // ================= CORS HEADERS =================
  const allowedOrigins = [
    'https://sini-kepoin.vercel.app',
    'https://sini-kepoin.vercel.app',
    'http://localhost:3000',
    'http://127.0.0.1:3000'
  ];
  
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
  
  // ================= HANDLE PREFLIGHT =================
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  // ================= ONLY ALLOW GET =================
  if (req.method !== 'GET') {
    return res.status(405).json({
      error: 'Method not allowed',
      allowed: ['GET']
    });
  }
  
  try {
    const { id, url, hash } = req.query;
    
    if (!id && !url && !hash) {
      return res.status(400).json({
        error: 'Missing identifier',
        required: 'id, url, or hash query parameter'
      });
    }
    
    // ================= RATE LIMITING =================
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const rateLimitKey = `report:${clientIp}`;
    
    const rateLimitData = global.reportRateLimitData || {};
    const now = Date.now();
    const windowMs = 60000;
    const maxRequests = 30;
    
    if (!rateLimitData[rateLimitKey]) {
      rateLimitData[rateLimitKey] = {
        count: 0,
        resetTime: now + windowMs
      };
    }
    
    const userData = rateLimitData[rateLimitKey];
    
    if (now > userData.resetTime) {
      userData.count = 0;
      userData.resetTime = now + windowMs;
    }
    
    if (userData.count >= maxRequests) {
      return res.status(429).json({
        error: 'Rate limit exceeded',
        retryAfter: Math.ceil((userData.resetTime - now) / 1000)
      });
    }
    
    userData.count++;
    global.reportRateLimitData = rateLimitData;
    
    // ================= FIND REPORT =================
    let reportData;
    let identifier;
    
    if (id) {
      identifier = `id:${id}`;
      reportData = reportCache.get(identifier);
    } else if (hash) {
      identifier = `hash:${hash}`;
      reportData = reportCache.get(identifier);
    } else if (url) {
      const urlHash = crypto.createHash('sha256').update(url).digest('hex').substring(0, 32);
      identifier = `hash:${urlHash}`;
      reportData = reportCache.get(identifier);
    }
    
    // ================= GENERATE MOCK REPORT IF NOT FOUND =================
    if (!reportData) {
      // This is a mock response for demonstration
      // In production, you would fetch from database
      
      const targetUrl = url || 'https://example.com';
      let parsedUrl;
      try {
        parsedUrl = new URL(targetUrl);
      } catch {
        parsedUrl = { hostname: 'unknown' };
      }
      
      // Generate realistic-looking mock data
      const malicious = Math.random() < 0.1 ? Math.floor(Math.random() * 30) + 5 : 0;
      const suspicious = Math.random() < 0.2 ? Math.floor(Math.random() * 15) : 0;
      const undetected = 72 - malicious - suspicious;
      const harmless = Math.floor(Math.random() * (undetected - 10));
      
      const status = malicious > 0 ? 'malicious' : suspicious > 0 ? 'suspicious' : 'clean';
      const reputation = Math.max(0, 100 - (malicious * 3) - (suspicious * 2));
      
      reportData = {
        id: id || `report_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
        url: targetUrl,
        hostname: parsedUrl.hostname,
        status: status,
        stats: {
          malicious,
          suspicious,
          undetected,
          harmless
        },
        reputation: reputation,
        last_analysis: Date.now() - Math.floor(Math.random() * 86400000),
        created_at: Date.now() - Math.floor(Math.random() * 604800000), // Within a week
        updated_at: Date.now()
      };
      
      // Cache for 1 hour
      if (identifier) {
        reportCache.set(identifier, reportData);
        
        // Clean up old cache entries (older than 24 hours)
        setTimeout(() => {
          reportCache.delete(identifier);
        }, 3600000);
      }
    }
    
    // ================= SANITIZE RESPONSE =================
    const sanitizedReport = {
      id: reportData.id,
      url: reportData.url,
      hostname: reportData.hostname,
      status: reportData.status,
      created_at: new Date(reportData.created_at).toISOString(),
      updated_at: new Date(reportData.updated_at).toISOString(),
      stats: reportData.stats,
      reputation: reportData.reputation,
      last_analysis: new Date(reportData.last_analysis).toISOString()
    };
    
    // ================= SEND RESPONSE =================
    return res.status(200).json({
      success: true,
      data: sanitizedReport,
      meta: {
        cached: reportCache.has(identifier),
        ttl: 3600,
        identifier: identifier
      }
    });
    
  } catch (error) {
    console.error('Report API error:', error);
    
    return res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
};
