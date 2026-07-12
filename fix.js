const fs = require('fs');
let h = fs.readFileSync('index.html', 'utf8');

// Remove ALL emojis
h = h.replace(/[\uD800-\uDFFF]/g, '');
h = h.replace(/[\u2600-\u27FF]/g, '');

fs.writeFileSync('index.html', h);
console.log('All emojis removed!');