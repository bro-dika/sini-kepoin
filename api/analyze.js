// api/analyze.js - Vercel Serverless Function for Detailed Analysis
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
    const { id, url } = req.query;
    
    if (!id && !url) {
      return res.status(400).json({
        error: 'Missing parameter',
        required: 'id or url query parameter'
      });
    }
    
    // ================= RATE LIMITING =================
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const rateLimitKey = `analyze:${clientIp}`;
    
    const rateLimitData = global.analyzeRateLimitData || {};
    const now = Date.now();
    const windowMs = 60000;
    const maxRequests = 20;
    
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
    global.analyzeRateLimitData = rateLimitData;
    
    // ================= GENERATE ANALYSIS DATA =================
    // This is mock data for demonstration
    // In production, this would fetch from VirusTotal or your database
    
    const targetUrl = url || 'https://example.com';
    let hostname = 'unknown';
    
    try {
      hostname = new URL(targetUrl).hostname;
    } catch (e) {
      // Use provided URL as-is if parsing fails
    }
    
    // Generate realistic analysis data
    const analysisData = {
      id: id || `analysis_${Date.now()}`,
      url: targetUrl,
      hostname: hostname,
      analysis: {
        whois: {
          registrar: Math.random() > 0.5 ? 'GoDaddy' : 'NameCheap',
          created_date: new Date(Date.now() - Math.floor(Math.random() * 31536000000)).toISOString(), // Within a year
          updated_date: new Date(Date.now() - Math.floor(Math.random() * 2592000000)).toISOString(), // Within a month
          expiration_date: new Date(Date.now() + Math.floor(Math.random() * 31536000000)).toISOString(), // Next year
          name_servers: ['ns1.example.com', 'ns2.example.com']
        },
        ssl: {
          valid: targetUrl.startsWith('https://') || Math.random() > 0.3,
          issuer: targetUrl.startsWith('https://') ? 'Let\'s Encrypt' : null,
          protocol: targetUrl.startsWith('https://') ? 'TLS 1.3' : null,
          expiration: targetUrl.startsWith('https://') ? 
            new Date(Date.now() + Math.floor(Math.random() * 2592000000)).toISOString() : null
        },
        technologies: [
          { name: 'Nginx', confidence: 95 },
          { name: 'PHP', confidence: 80 },
          { name: 'jQuery', confidence: 70 },
          { name: 'Bootstrap', confidence: 65 }
        ].filter(() => Math.random() > 0.3),
        security_headers: {
          'X-Frame-Options': Math.random() > 0.5 ? 'DENY' : 'SAMEORIGIN',
          'X-Content-Type-Options': Math.random() > 0.7 ? 'nosniff' : null,
          'Strict-Transport-Security': targetUrl.startsWith('https://') ? 'max-age=31536000' : null
        },
        categories: ['technology', 'information'].filter(() => Math.random() > 0.5),
        popularity: {
          rank: Math.floor(Math.random() * 1000000) + 1,
          delta: Math.floor(Math.random() * 100) - 50
        },
        threat_actors: Math.random() > 0.8 ? ['APT29', 'Lazarus Group'] : [],
        malware_families: Math.random() > 0.9 ? ['Emotet', 'TrickBot'] : []
      },
      recommendations: [
        Math.random() > 0.3 ? 'Enable HSTS header' : null,
        Math.random() > 0.5 ? 'Implement CSP header' : null,
        Math.random() > 0.7 ? 'Update SSL certificate' : null,
        targetUrl.startsWith('http://') ? 'Migrate to HTTPS' : null
      ].filter(Boolean),
      generated_at: new Date().toISOString()
    };
    
    // ================= SEND RESPONSE =================
    return res.status(200).json({
      success: true,
      data: analysisData,
      meta: {
        source: 'mock_data',
        cache_control: 'public, max-age=300'
      }
    });
    
  } catch (error) {
    console.error('Analyze API error:', error);
    
    return res.status(500).json({
      error: 'Internal server error',
      code: 'INTERNAL_ERROR'
    });
  }
};
