const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

async function getUserFromToken(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return null;
  const token = authHeader.replace('Bearer ', '');
  const { data, error } = await supabaseAdmin.auth.getUser(token);
  if (error) return null;
  return data.user;
}

const PLAN_LIMITS = { free: 5, client: 20, paid: null };

async function getOrCreateAccess(userId, email) {
  const { data: existing } = await supabaseAdmin.from('user_access').select('*').eq('user_id', userId).maybeSingle();
  if (existing) return existing;
  const { data: created, error } = await supabaseAdmin.from('user_access').insert({
    user_id: userId, email, plan: 'free', daily_limit: PLAN_LIMITS.free, is_admin: false
  }).select().maybeSingle();
  if (error) return { user_id: userId, email, plan: 'free', daily_limit: PLAN_LIMITS.free, is_admin: false };
  return created;
}

async function getTodayUsageCount(userId) {
  const startOfDay = new Date();
  startOfDay.setHours(0, 0, 0, 0);
  const { count } = await supabaseAdmin.from('search_history').select('*', { count: 'exact', head: true }).eq('user_id', userId).gte('created_at', startOfDay.toISOString());
  return count || 0;
}

async function getTotalUsageCount(userId) {
  const { count } = await supabaseAdmin.from('search_history').select('*', { count: 'exact', head: true }).eq('user_id', userId);
  return count || 0;
}

async function enforceAccess(req, res) {
  const user = await getUserFromToken(req);
  if (!user) { res.status(401).json({ error: 'Not logged in' }); return null; }
  const access = await getOrCreateAccess(user.id, user.email);
  if (access.is_admin || access.plan === 'paid') return user;

  // Free plan: one-time lifetime cap (no daily reset)
  if (access.plan === 'free') {
    const used = await getTotalUsageCount(user.id);
    const limit = access.daily_limit;
    if (used >= limit) {
      res.status(403).json({ error: `You've used all ${limit} free searches on the Free plan. Upgrade to Client (20/day) or Paid (unlimited) to keep going.` });
      return null;
    }
    return user;
  }

  // Client (and any other plan): daily reset
  const limit = access.daily_limit;
  const used = await getTodayUsageCount(user.id);
  if (used >= limit) {
    res.status(403).json({ error: `Daily limit reached (${used}/${limit} on the ${access.plan} plan). Try again tomorrow, or upgrade to Paid for unlimited searches.` });
    return null;
  }
  return user;
}

const app = express();

// Security headers. CSP is left off because this app relies on inline <script>/<style>
// throughout its pages — turning it on without a full rewrite would break the UI.
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

// Only allow requests from our own site (plus localhost for local development).
const ALLOWED_ORIGINS = [
  'https://ai-visibility-tool-omega.vercel.app',
  'http://localhost:3000'
];
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  }
}));

app.use(express.json());

// General rate limit for all API routes — protects Groq/Serper credits and keeps
// one runaway client from slowing the app down for everyone else.
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down and try again in a minute.' }
});
app.use('/api/', generalLimiter);

// The Geo-Grid scan fires ~121 external API calls per request — needs a much
// tighter limit so it can't be used to burn through Serper credits quickly.
const geoGridLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Geo-Grid scans are limited to 3 every 10 minutes. Please wait and try again.' }
});
app.use('/api/geo-grid', geoGridLimiter);

// Business search runs on every keystroke (debounced client-side), give it a bit more room.
const businessSearchLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 40,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/business-search', businessSearchLimiter);

async function callGroq(prompt) {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${process.env.GROQ_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: 'llama-3.3-70b-versatile', messages: [{ role: 'user', content: prompt }] })
    });
    const data = await response.json();
    return data.choices?.[0]?.message?.content || "Analysis failed";
}

async function callSerper(query, type = 'search') {
    const response = await fetch(`https://google.serper.dev/${type}`, {
        method: 'POST',
        headers: { 'X-API-KEY': process.env.SERPER_API_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({ q: query })
    });
    return await response.json();
}

// Rejects anything that isn't a real-looking domain (e.g. "yoursite.com"), so
// garbage or script-like input never reaches Serper/Groq and never burns a search credit.
function isValidDomain(domain) {
    if (!domain || typeof domain !== 'string') return false;
    const cleaned = domain.trim().toLowerCase()
        .replace(/^https?:\/\//, '')
        .replace(/^www\./, '')
        .split('/')[0]
        .split('?')[0];
    if (cleaned.length === 0 || cleaned.length > 253) return false;
    const domainRegex = /^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
    return domainRegex.test(cleaned);
}

// General guard for free-text fields (keyword, city, business name, location).
// Blocks obvious HTML/script injection attempts and empty/oversized input.
function isSafeText(str, maxLen = 120) {
    if (!str || typeof str !== 'string') return false;
    const trimmed = str.trim();
    if (trimmed.length === 0 || trimmed.length > maxLen) return false;
    if (/[<>]/.test(trimmed)) return false;
    return true;
}

function domainError(res) {
    return res.status(400).json({ error: 'Please enter a valid domain (e.g. yoursite.com).' });
}
function textError(res, field) {
    return res.status(400).json({ error: `Please enter a valid ${field}.` });
}

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/app.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'app.html'));
});

app.use(express.static(__dirname));

// 1. AI Visibility
app.post('/api/visibility', async (req, res) => {
    const user = await enforceAccess(req, res);
    if (!user) return;
    const { keyword, domain, competitors } = req.body;
    if (!isSafeText(keyword, 150)) return textError(res, 'keyword');
    if (!isValidDomain(domain)) return domainError(res);
    if (competitors && !isSafeText(competitors, 300)) return textError(res, 'competitors list');
    try {
        const searchData = await callSerper(keyword);
        const results = searchData.organic?.slice(0, 10).map((r, i) => `Rank ${i+1}: ${r.link} - ${r.title}`).join('\n') || 'No results';
        const competitorScores = competitors ? competitors.split(',').map(c => `${c.trim()}: [0-100]%`).join('\n') : '';
        const prompt = `You are an AEO (Answer Engine Optimization) expert consultant. Analyze AI Search visibility for "${domain}" for keyword "${keyword}".
Real Google Results:\n${results}\nCompetitors: ${competitors || 'none'}

Respond in this EXACT format:
VISIBILITY STATUS:
[Mentioned/Not Mentioned] - [specific rank or reason]

TOP 5 RECOMMENDATIONS:
1. [website] - [why ranking]
2. [website] - [why ranking]
3. [website] - [why ranking]
4. [website] - [why ranking]
5. [website] - [why ranking]

VISIBILITY SCORE:
${domain}: [0-100]%
${competitorScores}

COMPETITOR INSIGHT:
[2 lines comparing domain with competitors based on real data]

KEY ISSUES:
1. [specific reason this domain is weak or missing in AI/Google visibility for this keyword]
2. [specific reason]
3. [specific reason]

HOW TO IMPROVE VISIBILITY:
1. [specific, actionable SEO/AEO fix tied to the issues above]
2. [specific, actionable SEO/AEO fix]
3. [specific, actionable SEO/AEO fix]`;
        const ai_response = await callGroq(prompt);
        const mentioned = results.toLowerCase().includes(domain.toLowerCase().replace('https://','').replace('http://','').replace('www.',''));
        res.json({ keyword, domain, mentioned, ai_response });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 2. Brand Sentiment
app.post('/api/sentiment', async (req, res) => {
    const user = await enforceAccess(req, res);
    if (!user) return;
    const { domain } = req.body;
    if (!isValidDomain(domain)) return domainError(res);
    try {
        const searchData = await callSerper(`${domain} reviews feedback`);
        const snippets = searchData.organic?.map(r => r.snippet).filter(Boolean).join('\n') || 'No data';
        const prompt = `You are a brand reputation and AEO expert. Analyze brand sentiment for "${domain}" from real Google snippets:\n${snippets}

Respond in this EXACT format:
SENTIMENT: [Positive/Neutral/Negative]
SENTIMENT SCORE: [0-100]%
BRAND WORDS: [word1, word2, word3, word4, word5]
BRAND DESCRIPTION: [2 lines]

KEY ISSUES:
1. [specific reputation weakness or gap found]
2. [specific reputation weakness or gap]
3. [specific reputation weakness or gap]

IMPROVEMENT TIPS:
1. [specific, actionable fix tied to the issues above]
2. [specific, actionable fix]
3. [specific, actionable fix]`;
        const ai_response = await callGroq(prompt);
        res.json({ ai_response });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 3. Why Not Ranking
app.post('/api/whynotranking', async (req, res) => {
    const user = await enforceAccess(req, res);
    if (!user) return;
    const { keyword, domain } = req.body;
    if (!isSafeText(keyword, 150)) return textError(res, 'keyword');
    if (!isValidDomain(domain)) return domainError(res);
    try {
        const searchData = await callSerper(keyword);
        const top = searchData.organic?.slice(0, 5).map(r => `${r.link} - ${r.snippet}`).join('\n') || 'No data';
        const prompt = `You are an SEO/AEO gap-analysis expert. Analyze why "${domain}" is not ranking for "${keyword}".
Top Google Results:\n${top}

Respond in this EXACT format:
RANKING STATUS: [Not Ranking/Partially Ranking/Ranking]

KEY ISSUES:
1. [specific reason]
2. [specific reason]
3. [specific reason]

HOW TO IMPROVE VISIBILITY:
1. [specific, actionable fix]
2. [specific, actionable fix]
3. [specific, actionable fix]
4. [specific, actionable fix]

PRIORITY ACTION: [single most important action to take first]
TIMELINE: [estimated time to see results]`;
        const ai_response = await callGroq(prompt);
        res.json({ ai_response });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 4. Local AI
app.post('/api/local', async (req, res) => {
    const user = await enforceAccess(req, res);
    if (!user) return;
    const { keyword, domain, city } = req.body;
    if (!isSafeText(keyword, 150)) return textError(res, 'keyword');
    if (!isValidDomain(domain)) return domainError(res);
    if (!isSafeText(city, 100)) return textError(res, 'city');
    try {
        const searchData = await callSerper(`${keyword} in ${city}`, 'places');
        const places = searchData.places?.map(p => `${p.title} - ${p.address} (${p.rating || 'N/A'} stars)`).join('\n') || 'No local data';
        const prompt = `You are a Local SEO/AEO expert. Analyze local AI visibility for "${domain}" in "${city}" for "${keyword}".
Real Local Google Results:\n${places}

Respond in this EXACT format:
LOCAL VISIBILITY STATUS: [High/Medium/Low]
LOCAL SCORE: [0-100]%
TOP LOCAL COMPETITORS:
1. [competitor] - [reason]
2. [competitor] - [reason]
3. [competitor] - [reason]

KEY ISSUES:
1. [specific local visibility weakness]
2. [specific local visibility weakness]
3. [specific local visibility weakness]

LOCAL SEO TIPS:
1. [specific, actionable fix]
2. [specific, actionable fix]
3. [specific, actionable fix]

LOCAL INSIGHT: [2 lines]`;
        const ai_response = await callGroq(prompt);
        res.json({ ai_response });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 5. Citation Score
app.post('/api/citation', async (req, res) => {
    const user = await enforceAccess(req, res);
    if (!user) return;
    const { domain, keyword } = req.body;
    if (!isValidDomain(domain)) return domainError(res);
    if (!isSafeText(keyword, 150)) return textError(res, 'keyword/topic');
    try {
        const searchData = await callSerper(`"${domain}" ${keyword} mentioned cited`);
        const results = searchData.organic?.map(r => `${r.link} - ${r.snippet}`).join('\n') || 'No data';
        const prompt = `You are an authority/citation-building AEO expert. Analyze citation authority for "${domain}" regarding "${keyword}".
Real Google Data:\n${results}

Respond in this EXACT format:
CITATION SCORE: [0-100]%
CITATION FREQUENCY: [Never/Rarely/Sometimes/Often/Frequently]
CITATION STRENGTH: [Weak/Moderate/Strong/Authoritative]
CITED FOR:
1. [topic]
2. [topic]
3. [topic]

KEY ISSUES:
1. [specific reason citation authority is weak]
2. [specific reason]
3. [specific reason]

HOW TO IMPROVE CITATIONS:
1. [specific, actionable fix]
2. [specific, actionable fix]
3. [specific, actionable fix]

CITATION INSIGHT: [2 lines]`;
        const ai_response = await callGroq(prompt);
        res.json({ ai_response });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

async function geocodeAddress(address) {
    const response = await fetch(`https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(address)}&limit=1`, {
        headers: { 'User-Agent': 'AEO-Tracker/1.0' }
    });
    const data = await response.json();
    if (data && data[0]) return { lat: parseFloat(data[0].lat), lng: parseFloat(data[0].lon) };
    return null;
}

// 5b. Business Search (autocomplete for GMB Geo-Grid tool)
// Does not consume daily quota - it's just a lookup, not a full report.
app.post('/api/business-search', async (req, res) => {
    const user = await getUserFromToken(req);
    if (!user) return res.status(401).json({ error: 'Not logged in' });
    const { query, location } = req.body;
    if (!query || query.trim().length < 2) return res.json({ results: [] });
    if (!isSafeText(query, 120)) return textError(res, 'business name');
    if (location && !isSafeText(location, 120)) return textError(res, 'location');
    try {
        const q = location ? `${query} ${location}` : query;
        const response = await fetch('https://google.serper.dev/places', {
            method: 'POST',
            headers: { 'X-API-KEY': process.env.SERPER_API_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({ q })
        });
        const data = await response.json();
        const results = (data.places || []).slice(0, 8).map(p => ({
            title: p.title,
            address: p.address || '',
            rating: p.rating || null,
            ratingCount: p.ratingCount || p.reviews || null,
            cid: p.cid || null,
            website: p.website || null,
            phoneNumber: p.phoneNumber || null,
            latitude: p.latitude || null,
            longitude: p.longitude || null
        }));
        res.json({ results });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 6. GMB Geo-Grid Rank Tracker (dense 11x11 = 121 point grid, business-search based)
app.post('/api/geo-grid', async (req, res) => {
    const user = await enforceAccess(req, res);
    if (!user) return;
    const { businessName, keyword, location, radiusKm } = req.body;
    if (!isSafeText(businessName, 150)) return textError(res, 'business name');
    if (!isSafeText(keyword, 150)) return textError(res, 'keyword');
    if (!isSafeText(location, 150)) return textError(res, 'location');
    try {
        const center = await geocodeAddress(location);
        if (!center) return res.status(400).json({ error: 'Could not find that location. Try a more specific address or city name.' });

        const radius = Math.min(Math.max(parseFloat(radiusKm) || 5, 1), 10);

        // Dense grid: 11x11 = 121 points spread evenly across the radius
        const GRID_SIZE = 11;
        const half = Math.floor(GRID_SIZE / 2);
        const stepDeg = (radius / 111) / half;
        const points = [];
        for (let row = -half; row <= half; row++) {
            for (let col = -half; col <= half; col++) {
                points.push({ lat: center.lat + row * stepDeg, lng: center.lng + col * stepDeg });
            }
        }

        const nameLower = businessName.toLowerCase().trim();

        // Run in parallel batches so we don't blow the serverless function timeout
        const BATCH_SIZE = 20;
        const results = [];
        for (let i = 0; i < points.length; i += BATCH_SIZE) {
            const batch = points.slice(i, i + BATCH_SIZE);
            const batchResults = await Promise.all(batch.map(async (p) => {
                try {
                    const searchResponse = await fetch('https://google.serper.dev/places', {
                        method: 'POST',
                        headers: { 'X-API-KEY': process.env.SERPER_API_KEY, 'Content-Type': 'application/json' },
                        body: JSON.stringify({ q: keyword, ll: `@${p.lat},${p.lng},14z` })
                    });
                    const data = await searchResponse.json();
                    const places = data.places || [];
                    let rank = null;
                    places.forEach((pl, idx) => {
                        const title = (pl.title || '').toLowerCase();
                        if (rank === null && title.includes(nameLower)) rank = idx + 1;
                    });
                    const competitors = places
                        .filter(pl => !(pl.title || '').toLowerCase().includes(nameLower))
                        .slice(0, 5)
                        .map((pl, idx) => ({ name: pl.title, rating: pl.rating || null, rank: idx + 1 }));
                    return { lat: p.lat, lng: p.lng, rank, competitors, totalFound: places.length };
                } catch (e) {
                    return { lat: p.lat, lng: p.lng, rank: null, competitors: [], totalFound: 0 };
                }
            }));
            results.push(...batchResults);
        }

        // Aggregate unique competitors with their average rank + how often they appeared
        const compSum = {};
        const compCount = {};
        results.forEach(r => r.competitors.forEach(c => {
            compSum[c.name] = (compSum[c.name] || 0) + c.rank;
            compCount[c.name] = (compCount[c.name] || 0) + 1;
        }));
        const competitorList = Object.keys(compSum).map(name => ({
            name,
            avgRank: parseFloat((compSum[name] / compCount[name]).toFixed(2)),
            appearances: compCount[name]
        })).sort((a, b) => a.avgRank - b.avgRank).slice(0, 30);

        const total = results.length;
        const found = results.filter(r => r.rank !== null);
        const high = results.filter(r => r.rank !== null && r.rank <= 3).length;
        const med = results.filter(r => r.rank !== null && r.rank > 3 && r.rank <= 10).length;
        const low = results.filter(r => r.rank !== null && r.rank > 10).length;
        const out = results.filter(r => r.rank === null).length;
        const avgRank = found.length ? parseFloat((found.reduce((a, r) => a + r.rank, 0) / found.length).toFixed(2)) : null;

        res.json({
            center,
            points: results,
            businessName,
            keyword,
            radiusKm: radius,
            uniqueCompetitors: competitorList.length,
            competitorList,
            stats: {
                avgRank,
                highPct: total ? Math.round((high / total) * 100) : 0,
                medPct: total ? Math.round((med / total) * 100) : 0,
                lowPct: total ? Math.round((low / total) * 100) : 0,
                outPct: total ? Math.round((out / total) * 100) : 0,
                total
            }
        });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// Check current user's access/plan/usage
app.get('/api/check-access', async (req, res) => {
  const user = await getUserFromToken(req);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  const access = await getOrCreateAccess(user.id, user.email);
  const unlimited = access.is_admin || access.plan === 'paid';
  let used = 0;
  let limitType = 'daily';
  if (!unlimited) {
    if (access.plan === 'free') {
      used = await getTotalUsageCount(user.id);
      limitType = 'total';
    } else {
      used = await getTodayUsageCount(user.id);
      limitType = 'daily';
    }
  }
  res.json({
    plan: access.plan,
    daily_limit: access.daily_limit,
    is_admin: access.is_admin,
    used_today: used,
    limit_type: limitType,
    unlimited
  });
});

// Admin: list all users
app.get('/api/admin/users', async (req, res) => {
  const user = await getUserFromToken(req);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  const access = await getOrCreateAccess(user.id, user.email);
  if (!access.is_admin) return res.status(403).json({ error: 'Admin access only' });
  const { data, error } = await supabaseAdmin.from('user_access').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  const withUsage = await Promise.all(data.map(async u => ({ ...u, used_today: await getTodayUsageCount(u.user_id) })));
  res.json({ users: withUsage });
});

// Admin: update a user's plan / limit / admin flag
app.post('/api/admin/update-user', async (req, res) => {
  const user = await getUserFromToken(req);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  const access = await getOrCreateAccess(user.id, user.email);
  if (!access.is_admin) return res.status(403).json({ error: 'Admin access only' });
  const { target_user_id, plan, daily_limit } = req.body;
  const updates = {};
  if (plan) { updates.plan = plan; updates.daily_limit = daily_limit !== undefined ? parseInt(daily_limit) : PLAN_LIMITS[plan]; }
  else if (daily_limit !== undefined) { updates.daily_limit = parseInt(daily_limit); }
  const { error } = await supabaseAdmin.from('user_access').update(updates).eq('user_id', target_user_id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.post('/api/history', async (req, res) => {
  const user = await getUserFromToken(req);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  const { tool_type, keyword, domain, city, result_summary, full_response } = req.body;
  const { error } = await supabaseAdmin.from('search_history').insert({
    user_id: user.id, tool_type, keyword, domain, city, result_summary, full_response
  });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// Get user's search history
app.get('/api/history', async (req, res) => {
  const user = await getUserFromToken(req);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  const { data, error } = await supabaseAdmin
    .from('search_history')
    .select('*')
    .eq('user_id', user.id)
    .order('created_at', { ascending: false })
    .limit(50);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ history: data });
});

// Delete a history item
app.delete('/api/history/:id', async (req, res) => {
  const user = await getUserFromToken(req);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  const { error } = await supabaseAdmin
    .from('search_history')
    .delete()
    .eq('id', req.params.id)
    .eq('user_id', user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// Catch-all: anything that throws unexpectedly returns a clean error instead of crashing.
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json({ error: 'Request blocked (CORS).' });
  }
  res.status(500).json({ error: 'Something went wrong on our end. Please try again.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Advanced AEO Suite running on port ${PORT}`));
module.exports = app;