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

// --- Functions (Groq & Serper) ---
async function callGroq(prompt) {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${process.env.GROQ_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: 'llama-3.3-70b-versatile', messages: [{ role: 'user', content: prompt }] }  )
    });
    const data = await response.json();
    return data.choices?.[0]?.message?.content || "Analysis failed";
}

async function callSerper(query, type = 'search') {
    const response = await fetch(`https://google.serper.dev/${type}`, {
        method: 'POST',
        headers: { 'X-API-KEY': process.env.SERPER_API_KEY, 'Content-Type': 'application/json' },
        body: JSON.stringify({ q: query }  )
    });
    return await response.json();
}

// --- Routes (Login Page First) ---
app.get('/', (req, res) => { 
    res.sendFile(path.join(__dirname, 'login.html')); 
});

app.get('/index.html', (req, res) => { 
    res.sendFile(path.join(__dirname, 'index.html')); 
});

// AB STATIC FILES SERVE KAREIN (Taki ye default index.html na uthaye)
app.use(express.static(__dirname));

// --- API Endpoints ---

// 1. AI Visibility
app.post('/api/visibility', async (req, res) => {
    const { keyword, domain, competitors } = req.body;
    try {
        const searchData = await callSerper(keyword);
        const results = searchData.organic?.slice(0, 10).map((r, i) => `Rank ${i+1}: ${r.link} - ${r.title}`).join('\n') || 'No results';
        const competitorScores = competitors ? competitors.split(',').map(c => `${c.trim()}: [0-100]%`).join('\n') : '';
        const prompt = `You are an AEO Expert. Analyze AI Search visibility for "${domain}" for keyword "${keyword}".
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
[2 lines comparing domain with competitors based on real data]`;
        const ai_response = await callGroq(prompt);
        const mentioned = results.toLowerCase().includes(domain.toLowerCase().replace('https://','' ).replace('http://','' ).replace('www.',''));
        res.json({ keyword, domain, mentioned, ai_response });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 2. Brand Sentiment
app.post('/api/sentiment', async (req, res) => {
    const { domain } = req.body;
    try {
        const searchData = await callSerper(`${domain} reviews feedback`);
        const snippets = searchData.organic?.map(res => res.snippet).join('\n');
        const prompt = `Analyze brand reputation for "${domain}".
        Data:\n${snippets}\n
        Provide:
        1. SENTIMENT: (Positive/Neutral/Negative)
        2. EMOTION BREAKDOWN: (Trust, Concern, Satisfaction levels)
        3. TOP QUOTES: 2 representative snippets.
        4. SENTIMENT SCORE: [0-100]%
        5. REPUTATION FIX: 2 steps to improve public perception.`;
        const ai_response = await callGroq(prompt);
        res.json({ ai_response });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 3. Why Not Ranking
app.post('/api/whynotranking', async (req, res) => {
    const { keyword, domain } = req.body;
    try {
        const searchData = await callSerper(keyword);
        const top = searchData.organic?.slice(0, 3).map(res => res.link).join('\n');
        const prompt = `Gap Analysis for "${domain}" on keyword "${keyword}".
        Top Ranking Sites:\n${top}\n
        Provide:
        1. RANKING STATUS: (Current position or 'Not Found')
        2. CONTENT GAP: What topics are competitors covering that "${domain}" is missing?
        3. TECHNICAL GAP: (Speed, Mobile-friendliness, Schema).
        4. KEYWORD DIFFICULTY: (Easy/Medium/Hard) + Reason.
        5. PRIORITY FIX: The #1 thing to change today.`;
        const ai_response = await callGroq(prompt);
        res.json({ ai_response });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 4. Local AI
app.post('/api/local', async (req, res) => {
    const { keyword, domain, city } = req.body;
    try {
        const searchData = await callSerper(`${keyword} in ${city}`, 'places');
        const places = searchData.places?.map(p => `${p.title} (${p.rating} stars)`).join('\n');
        const prompt = `Local AI Visibility for "${domain}" in "${city}".
        Local Listings:\n${places}\n
        Provide:
        1. MAP PRESENCE: (Strong/Weak/None).
        2. NAP CONSISTENCY: (Consistent/Inconsistent).
        3. LOCAL SCORE: [0-100]%.
        4. TOP LOCAL COMPETITORS: List 3.
        5. LOCAL INSIGHT: One tip to dominate local AI search.`;
        const ai_response = await callGroq(prompt);
        res.json({ ai_response });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 5. Citation Score
app.post('/api/citation', async (req, res) => {
    const { domain, keyword } = req.body;
    try {
        const searchData = await callSerper(`"${domain}" ${keyword} news wikipedia`);
        const prompt = `Authority Analysis for "${domain}" regarding "${keyword}".
        Provide:
        1. CITATION SCORE: [0-100]%.
        2. AUTHORITY BREAKDOWN: (High/Medium/Low authority mentions).
        3. MENTION CONTEXT: (Educational, Commercial, News).
        4. TOP SOURCES: 3 domains citing you.
        5. CITATION HEALTH: (Healthy/Needs Growth).`;
        const ai_response = await callGroq(prompt);
        res.json({ ai_response });
    } catch (error) { res.status(500).json({ error: error.message }); }
});
// Save search to history
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
