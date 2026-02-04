import fetch from 'node-fetch';

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  
  try {
    const { url } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }
    
    console.log(`Processing URL: ${url}`);
    
    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    
    if (!apiKey) {
      console.error('VirusTotal API key is missing');
      return res.status(500).json({ 
        error: 'API configuration error',
        details: 'Contact administrator to configure VirusTotal API key'
      });
    }
    
    // Step 1: Submit URL to VirusTotal
    const submitRes = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `url=${encodeURIComponent(url)}`
    });
    
    if (!submitRes.ok) {
      const errorText = await submitRes.text();
      console.error('VirusTotal submit error:', submitRes.status, errorText);
      
      if (submitRes.status === 401) {
        return res.status(500).json({ 
          error: 'Invalid API Key',
          message: 'VirusTotal API key is invalid or expired' 
        });
      }
      
      if (submitRes.status === 429) {
        return res.status(429).json({ 
          error: 'Rate Limit Exceeded',
          message: 'Too many requests to VirusTotal API. Please try again later.' 
        });
      }
      
      throw new Error(`VirusTotal API error: ${submitRes.status}`);
    }
    
    const submitData = await submitRes.json();
    const analysisId = submitData.data.id;
    console.log(`Analysis ID: ${analysisId}`);
    
    // Step 2: Wait for analysis (3 seconds)
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    // Step 3: Get analysis results
    const analysisRes = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: {
          'x-apikey': apiKey,
        },
      }
    );
    
    if (!analysisRes.ok) {
      throw new Error(`Failed to get analysis: ${analysisRes.status}`);
    }
    
    const analysisData = await analysisRes.json();
    
    // Format response for frontend
    const formattedResponse = formatResponse(analysisData, url);
    
    return res.status(200).json(formattedResponse);
    
  } catch (error) {
    console.error('API Error:', error);
    
    // Return error with details
    return res.status(500).json({
      error: 'Scan failed',
      message: error.message,
      details: 'Please check the URL and try again'
    });
  }
}

// Format VirusTotal response for frontend
function formatResponse(vtData, originalUrl) {
  const attributes = vtData.data.attributes;
  const stats = attributes.stats || { malicious: 0, suspicious: 0, undetected: 0, harmless: 0 };
  const results = attributes.results || {};
  
  // Create vendor list
  const last_analysis_results = {};
  Object.entries(results).forEach(([vendor, data]) => {
    last_analysis_results[vendor] = {
      category: data.category || 'undetected',
      result: data.result || 'undetected',
      method: data.method || 'blacklist'
    };
  });
  
  return {
    data: {
      attributes: {
        stats: {
          malicious: stats.malicious || 0,
          suspicious: stats.suspicious || 0,
          undetected: stats.undetected || 0,
          harmless: stats.harmless || 0
        },
        status: stats.malicious > 0 ? 'malicious' : 
               stats.suspicious > 0 ? 'suspicious' : 'harmless',
        reputation: calculateReputation(stats),
        last_analysis_date: attributes.date || Math.floor(Date.now() / 1000),
        last_analysis_results: last_analysis_results,
        url: originalUrl,
        title: `VirusTotal Scan: ${new URL(originalUrl).hostname}`,
        categories: attributes.categories || {},
        total_scans: Object.keys(results).length || 0
      }
    },
    meta: {
      source: 'virustotal',
      timestamp: new Date().toISOString(),
      scan_id: vtData.data.id
    }
  };
}

// Calculate reputation score (0-100)
function calculateReputation(stats) {
  const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
  if (total === 0) return 0;
  
  const score = 100 - ((stats.malicious * 100) / total) - ((stats.suspicious * 50) / total);
  return Math.max(0, Math.min(100, Math.round(score)));
}
