const express = require('express');
const cors = require('cors');
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

const app = express();
app.use(cors());
app.use(express.json());

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

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/app.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'app.html'));
});

app.use(express.static(__dirname));

// 1. AI Visibility
app.post('/api/visibility', async (req, res) => {
    const { keyword, domain, competitors } = req.body;
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
    const { domain } = req.body;
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
    const { keyword, domain } = req.body;
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
    const { keyword, domain, city } = req.body;
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
    const { domain, keyword } = req.body;
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

// 7. Geo-Grid Rank Map (3x3)
app.post('/api/geo-grid', async (req, res) => {
    const { domain, keyword, location } = req.body;
    try {
        const center = await geocodeAddress(location);
        if (!center) return res.status(400).json({ error: 'Could not find that location. Try a more specific address or city name.' });

        const offset = 0.012;
        const points = [];
        for (let row = -1; row <= 1; row++) {
            for (let col = -1; col <= 1; col++) {
                points.push({ lat: center.lat + row * offset, lng: center.lng + col * offset });
            }
        }

        const cleanDomain = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '').replace(/^www\./, '');
        const domainCore = cleanDomain.split('.')[0];

        const results = [];
        for (const p of points) {
            try {
                const searchResponse = await fetch('https://google.serper.dev/places', {
                    method: 'POST',
                    headers: { 'X-API-KEY': process.env.SERPER_API_KEY, 'Content-Type': 'application/json' },
                    body: JSON.stringify({ q: keyword, ll: `@${p.lat},${p.lng},14z` })
                });
                const data = await searchResponse.json();
                const places = data.places || [];
                let rank = null;
                let topName = places[0] ? places[0].title : null;
                places.forEach((pl, idx) => {
                    const site = ((pl.website || '') + ' ' + (pl.title || '')).toLowerCase();
                    if (rank === null && site.includes(domainCore)) rank = idx + 1;
                });
                results.push({ lat: p.lat, lng: p.lng, rank: rank, topName: topName });
            } catch (e) {
                results.push({ lat: p.lat, lng: p.lng, rank: null, topName: null });
            }
        }

        res.json({ center, points: results, domain: cleanDomain, keyword });
    } catch (error) { res.status(500).json({ error: error.message }); }
});


app.post('/api/local-heatmap', async (req, res) => {
    const { domain, keyword, cities } = req.body;
    try {
        const cityList = cities.split(',').map(c => c.trim()).filter(Boolean).slice(0, 8);
        let combinedData = '';
        for (const city of cityList) {
            const searchData = await callSerper(`${keyword} in ${city}`, 'places');
            const places = searchData.places?.slice(0, 5).map(p => `${p.title} (${p.rating || 'N/A'} stars)`).join(', ') || 'No local data found';
            combinedData += `\nCity: ${city}\nTop local results: ${places}\n`;
        }
        const prompt = `You are a Local AEO expert. Analyze local AI visibility for "${domain}" for keyword "${keyword}" across these cities, using real local search data:\n${combinedData}

For EACH city listed above, respond with exactly one line in this EXACT format (no extra text, no headers):
CityName: Score%: Status

Where Score is a number 0-100 reflecting how visible "${domain}" would likely be in AI/local search for that city, and Status is exactly one of: High, Medium, Low.
List all ${cityList.length} cities, one per line, in the same order given, nothing else before or after.`;
        const ai_response = await callGroq(prompt);
        res.json({ ai_response, cities: cityList });
    } catch (error) { res.status(500).json({ error: error.message }); }
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Advanced AEO Suite running on port ${PORT}`));
module.exports = app;