const https = require('https');
const crypto = require('crypto');
const url = require('url');

exports.handler = async function(event) {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json'
  };
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }
  try {
    const body = JSON.parse(event.body || '{}');
    const { params } = body;

    // Use environment variables — fall back to body for local dev
    const accountId = process.env.NS_ACCOUNT_ID || body.accountId;
    const restletUrl = process.env.NS_RESTLET_URL || body.restletUrl;
    const consumerKey = process.env.NS_CONSUMER_KEY || body.consumerKey;
    const consumerSecret = process.env.NS_CONSUMER_SECRET || body.consumerSecret;
    const tokenId = process.env.NS_TOKEN_ID || body.tokenId;
    const tokenSecret = process.env.NS_TOKEN_SECRET || body.tokenSecret;

    if (!restletUrl || !consumerKey || !tokenId) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: 'Missing credentials' }) };
    }

    const parsed = new url.URL(restletUrl);
    if (params) {
      Object.entries(params).forEach(([k, v]) => parsed.searchParams.set(k, v));
    }
    const fullUrl = parsed.toString();
    const authHeader = buildOAuth('GET', fullUrl, { consumerKey, consumerSecret, tokenId, tokenSecret, accountId });
    const data = await httpsGet(fullUrl, {
      'Authorization': authHeader,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    });
    return { statusCode: 200, headers, body: data };
  } catch(e) {
    return { statusCode: 502, headers, body: JSON.stringify({ error: e.message }) };
  }
};

function buildOAuth(method, fullUrl, cfg) {
  const { consumerKey, consumerSecret, tokenId, tokenSecret, accountId } = cfg;
  const parsed = new url.URL(fullUrl);
  const oauthParams = {
    oauth_consumer_key: consumerKey,
    oauth_token: tokenId,
    oauth_signature_method: 'HMAC-SHA256',
    oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
    oauth_nonce: crypto.randomBytes(16).toString('hex'),
    oauth_version: '1.0'
  };
  const allParams = { ...oauthParams };
  parsed.searchParams.forEach((v, k) => { allParams[k] = v; });
  const sorted = Object.keys(allParams).sort()
    .map(k => encodeURIComponent(k) + '=' + encodeURIComponent(allParams[k]))
    .join('&');
  const baseString = [
    method.toUpperCase(),
    encodeURIComponent(parsed.origin + parsed.pathname),
    encodeURIComponent(sorted)
  ].join('&');
  const signingKey = encodeURIComponent(consumerSecret) + '&' + encodeURIComponent(tokenSecret);
  const sig = crypto.createHmac('sha256', signingKey).update(baseString).digest('base64');
  oauthParams.oauth_signature = sig;
  const realm = accountId || '9356985';
  const parts = Object.keys(oauthParams)
    .map(k => `${encodeURIComponent(k)}="${encodeURIComponent(oauthParams[k])}"`)
    .join(', ');
  return `OAuth realm="${realm}", ${parts}`;
}

function httpsGet(fullUrl, headers) {
  return new Promise((resolve, reject) => {
    const parsed = new url.URL(fullUrl);
    const options = {
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers,
      timeout: 24000
    };
    const req = https.request(options, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(data);
        } else {
          reject(new Error(`NetSuite ${res.statusCode}: ${data.slice(0, 500)}`));
        }
      });
    });
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('NetSuite request timed out after 24s'));
    });
    req.on('error', reject);
    req.end();
  });
}
