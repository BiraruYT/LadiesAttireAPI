const express = require('express');
const SQLITE3 = require('better-sqlite3');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

const router = express.Router();

const dbPath = "./sqlitedb/dev-newarrivals.db";
const db = new SQLITE3(dbPath);

db.pragma('journal_mode = WAL');
db.prepare(`
  CREATE TABLE IF NOT EXISTS newarrivals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT,
    name TEXT,
    description TEXT,
    price INTEGER,
    image TEXT
  )
`).run();

router.get('/newarrivals', function(req, res) {
    const stmt = db.prepare('SELECT * FROM newarrivals');
    const products = stmt.all();
    const formattedProducts = products.map(product => {
        return `${product.id}: ${product.category}, ${product.name}, ${product.description}, ${product.price}, ${product.image}`;
    });
    res.json({ products: formattedProducts });
});

router.post('/newarrivals', function(req, res) {
    let body;

    try {
        body = req.body;
    } catch (err) {
        return res.status(500).json({
            message: 'Internal Server Error',
            csrfToken: req.csrfToken()
        });
    }

    if (!DOMPurify.sanitize(body.secret)) {
        return res.status(400).json({
            message: 'Your Not Supposed To Be Here, Well Lemme Give You A Hint',
            hint: 'It starts with a whisper and ends with a roar and i am CheapPlayz best friend. What am I?',
            csrfToken: req.csrfToken()
        });
    }
});

module.exports = router;