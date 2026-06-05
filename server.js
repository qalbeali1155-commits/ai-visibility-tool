const express = require('express');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.sendFile(path.resolve('index.html'));
});

app.post('/check', async (req, res) => {
  const { keyword, domain, competitors } = req.body;

  const competitorList = competitors ? competitors.split(',').map(c => c.trim()).join(', ') : 'none';

  try {
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [
          {
            role: 'user',
            content: `You are an AI visibility analyst. For the keyword "${keyword}", provide analysis in this exact format:

VISIBILITY STATUS:
Is "${domain}" relevant for this keyword? Answer Yes or No with one line reason.

TOP 5 RECOMMENDATIONS:
1. [website] - [one line reason]
2. [website] - [one line reason]
3. [website] - [one line reason]
4. [website] - [one line reason]
5. [website] - [one line reason]

VISIBILITY SCORE:
${domain}: [0-100]%
${competitorList !== 'none' ? competitorList.split(', ').map(c => `${c}: [0-100]%`).join('\n') : ''}

COMPETITOR INSIGHT:
Write 2 lines about how "${domain}" compares to competitors for this keyword.`
          }
        ]
      })
    });

    const data = await response.json();
    const answer = data.choices?.[0]?.message?.content || 'No response received';
    const mentioned = answer.toLowerCase().includes(domain.toLowerCase());

    res.json({
      keyword,
      domain,
      mentioned,
      ai_response: answer
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});