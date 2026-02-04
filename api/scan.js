// api/scan.js - Vercel Serverless Function for URL Scanning
const crypto = require('crypto');

module.exports = async (req, res) => {
  // ================= SECURITY HEADERS =================
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
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
  
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Request-ID, X-CSRF-Token');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Max-Age', '86400');
  
  // ================= HANDLE PREFLIGHT =================
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  // ================= ONLY ALLOW POST =================
  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'Method not allowed',
      allowed: ['POST']
    });
  }
  
  try {
    // ================= RATE LIMITING =================
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const rateLimitKey = `rate:${clientIp}`;
    
    // In production, use Redis or similar for rate limiting
    // For now, we'll implement a simple memory-based rate limiter
    const rateLimitData = global.rateLimitData || {};
    const now = Date.now();
    const windowMs = 60000; // 1 minute
    const maxRequests = 10;
    
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
        retryAfter: Math.ceil((userData.resetTime - now) / 1000),
        code: 'RATE_LIMIT'
      });
    }
    
    userData.count++;
    global.rateLimitData = rateLimitData;
    
    // ================= VALIDATE REQUEST =================
    const contentType = req.headers['content-type'];
    if (!contentType || !contentType.includes('application/json')) {
      return res.status(415).json({
        error: 'Unsupported media type',
        accepted: 'application/json'
      });
    }
    
    let body;
    try {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    } catch (e) {
      return res.status(400).json({
        error: 'Invalid JSON body'
      });
    }
    
    const { url, requestId, hash } = body;
    
    if (!url || !requestId) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['url', 'requestId']
      });
    }
    
    // ================= VALIDATE URL =================
    let parsedUrl;
    try {
      parsedUrl = new URL(url);
    } catch (e) {
      return res.status(400).json({
        error: 'Invalid URL format',
        details: 'Please provide a valid URL including protocol (http:// or https://)'
      });
    }
    
    // Validate protocol
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return res.status(400).json({
        error: 'Invalid protocol',
        details: 'Only HTTP and HTTPS URLs are allowed'
      });
    }
    
    // Validate length
    if (url.length > 2048) {
      return res.status(400).json({
        error: 'URL too long',
        maxLength: 2048
      });
    }
    
    // Check for blacklisted domains
    const blacklistedDomains = [
      'localhost',
      '127.0.0.1',
      '0.0.0.0',
      '192.168.',
      '10.',
      '172.16.',
      '169.254.',
      '::1'
    ];
    
    const hostname = parsedUrl.hostname.toLowerCase();
    for (const blacklisted of blacklistedDomains) {
      if (hostname.includes(blacklisted)) {
        return res.status(400).json({
          error: 'Domain not allowed',
          details: 'Private/internal domains cannot be scanned'
        });
      }
    }
    
    // Check hash integrity
    if (hash) {
      const expectedHash = crypto
        .createHash('sha256')
        .update(url + (process.env.HASH_SECRET || 'default-secret'))
        .digest('hex')
        .substring(0, 16);
      
      if (hash !== expectedHash) {
        return res.status(400).json({
          error: 'Request integrity check failed',
          code: 'INTEGRITY_ERROR'
        });
      }
    }
    
    // ================= CALL VIRUSTOTAL API =================
    const API_KEY = process.env.VIRUSTOTAL_API_KEY;
    
    if (!API_KEY) {
      console.error('VirusTotal API key not configured');
      return res.status(500).json({
        error: 'Service configuration error',
        code: 'CONFIG_ERROR'
      });
    }
    
    // First, submit URL for analysis
    const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'SiniKepoin/1.0'
      },
      body: new URLSearchParams({ url: url })
    });
    
    if (!submitResponse.ok) {
      const errorText = await submitResponse.text();
      console.error('VirusTotal submit error:', submitResponse.status, errorText);
      
      return res.status(submitResponse.status).json({
        error: 'Failed to submit URL for analysis',
        details: submitResponse.statusText,
        code: 'VT_SUBMIT_ERROR'
      });
    }
    
    const submitData = await submitResponse.json();
    const analysisId = submitData.data.id;
    
    // Wait for analysis to complete (polling)
    let analysisData;
    let attempts = 0;
    const maxAttempts = 10;
    
    while (attempts < maxAttempts) {
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      const analysisResponse = await fetch(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        {
          headers: {
            'x-apikey': API_KEY,
            'User-Agent': 'SiniKepoin/1.0'
          }
        }
      );
      
      if (!analysisResponse.ok) {
        attempts++;
        continue;
      }
      
      analysisData = await analysisResponse.json();
      
      if (analysisData.data.attributes.status === 'completed') {
        break;
      }
      
      attempts++;
    }
    
    if (!analysisData || analysisData.data.attributes.status !== 'completed') {
      return res.status(408).json({
        error: 'Analysis timeout',
        code: 'ANALYSIS_TIMEOUT'
      });
    }
    
    // ================= SANITIZE RESPONSE =================
    const attributes = analysisData.data.attributes;
    
    // Remove any potentially sensitive data
    const sanitizedData = {
      data: {
        attributes: {
          stats: attributes.stats,
          status: attributes.status,
          reputation: attributes.reputation || 0,
          last_analysis_date: attributes.last_analysis_date,
          last_analysis_results: attributes.last_analysis_results,
          url: url,
          title: `Scan results for ${parsedUrl.hostname}`,
          categories: attributes.categories || {},
          last_http_response_code: attributes.last_http_response_code,
          outgoing_links: [],
          redirected_url: null,
          ssl_info: attributes.ssl_info || { valid: url.startsWith('https://') }
        },
        type: 'analysis',
        id: analysisData.data.id
      },
      meta: {
        url_info: {
          id: submitData.data.id
        },
        request_id: requestId,
        timestamp: Date.now(),
        analysis_time: attempts * 2000 // Time taken for analysis
      }
    };
    
    // ================= LOG THE SCAN =================
    console.log(`Scan completed: ${parsedUrl.hostname}, ID: ${analysisId}, Request: ${requestId}`);
    
    // ================= SEND RESPONSE =================
    return res.status(200).json(sanitizedData);
    
  } catch (error) {
    console.error('Scan API error:', error);
    
    // Don't expose internal errors
    return res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR',
      requestId: req.body?.requestId || 'unknown'
    });
  }
};
