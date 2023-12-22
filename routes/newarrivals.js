const express = require('express');
const SQLITE3 = require('better-sqlite3');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);
const multer = require("multer");
const fs = require('fs');
const imageSize = require("image-size");
const keys = require('../js/keys');
const { productsDB } = require("../app");
const path = require("path");

const router = express.Router();
// noinspection JSUnusedGlobalSymbols
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, './uploads/images/newarrivals/temp/');
    },
    filename: function(req, file, cb) {
        cb(null, file.originalname);
    }
});
const uploadicon = multer({
    storage: storage,
    limits: { fileSize: 2 * 1024 * 1024 },
    fileFilter: function (req, file, cb) {
        if (file.size > 2 * 1024 * 1024) {
            cb(new Error('File size is too large.'));
        } else {
            cb(null, true);
        }
    }
});

const dbPath = productsDB;
let db;
try {
    db = new SQLITE3(dbPath);
} catch (err) {
    console.error('Failed to create database connection', err);
    process.exit(1);
}

db.pragma('journal_mode = WAL');
db.prepare(`
  CREATE TABLE IF NOT EXISTS newarrivals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT,
    name TEXT,
    description TEXT,
    price INTEGER,
    image TEXT,
    imageext TEXT
  )
`).run();

function deleteFile(path, res) {
    let normalizedPath = path.normalize(path);
    let absolutePath = path.resolve(normalizedPath);

    if (absolutePath.startsWith(`${path.resolve('./uploads/images/newarrivals/temp/')}`)) {
        fs.unlink(path.extname(absolutePath), (err) => {
            if (err) {
                handleError(err, res)
            }
        });
    }
    else {
        console.log('File is not in the temp folder.');
    }
}

function handleError(err, res) {
    console.log(err);
    return res.status(500).json({ message: 'Internal Server Error' });
}

router.get('/newarrivals', function(req, res) {
    const stmt = db.prepare('SELECT * FROM newarrivals');
    const products = stmt.all();

    if (products.err) {
        handleError(products.err, res);
    }

    if (products.length > 0) {
        const formattedProducts = products.map(product => {
            // noinspection JSUnresolvedReference
            return [`${product.id}: ${product.category},`, `${product.name},`, `${product.description},`, `${product.price},`, `${product.image}`, `${product.imageext}`];
        });

        return res.status(200).json({
            products: formattedProducts,
            csrfToken: req.csrfToken
        });
    }
    else {
        return res.status(400).json({
            message: 'No Products Found.',
            error: 'NO-PRODUCTS-FOUND',
            csrfToken: req.csrfToken()
        });
    }
});

router.post('/newarrivals', uploadicon.single('icon'), function(req, res) {
    let body;

    try {
        body = req.body;
    } catch (err) {
        handleError(err, res);
    }

    const icon = req.file;

    if (!icon) {
        return res.status(400).json({
            message: 'Missing file',
            error: "MISSING-FILE",
            csrfToken: req.csrfToken()
        });
    }

    if (DOMPurify.sanitize(body.secret) === null || DOMPurify.sanitize(body.secret) === '' || !DOMPurify.sanitize(body.secret)) {
        deleteFile(icon.path, res);
        return res.status(401).json({
            message: 'Unauthorized',
            error: 'UNAUTHORIZED',
            csrfToken: req.csrfToken()
        });
    }

    if (icon) {
        const dimensions = imageSize(icon);

        if (!dimensions.width || !dimensions.height) {
            deleteFile(icon.path, res);
            return res.status(400).json({
                message: 'Uploaded file is not an image.',
                error: 'NOT_AN_IMAGE',
            });
        }
    }

    if (DOMPurify.sanitize(body.secret) === keys.keys.postkey) {
        // noinspection JSUnresolvedReference
        if (!DOMPurify.sanitize(body.category) || !DOMPurify.sanitize(body.name) || !DOMPurify.sanitize(body.description) || !DOMPurify.sanitize(body.price)) {
            deleteFile(icon.path, res);
            return res.status(400).json({
                message: 'Missing Information',
                error: "MISSING-INFORMATION",
                csrfToken: req.csrfToken()
            });
        }

        const sanitizedCategory = DOMPurify.sanitize(body.category);
        const sanitizedName = DOMPurify.sanitize(body.name);
        const sanitizedDescription = DOMPurify.sanitize(body.description);

        // noinspection JSUnresolvedReference
        const parsedPrice = Number.parseInt(body.price);

        if (isNaN(parsedPrice)) {
            deleteFile(icon.path, res);
            return res.status(400).json({
                message: 'Invalid price',
                error: "INVALID-PRICE",
                csrfToken: req.csrfToken()
            });
        }

        // noinspection JSUnresolvedReference
        if (typeof sanitizedCategory !== 'string' || typeof sanitizedName !== 'string' || typeof sanitizedDescription !== 'string' || typeof parsedPrice !== 'number') {
            deleteFile(icon.path, res);
            return res.status(400).json({
                message: 'Invalid Information',
                error: "INVALID-INFORMATION",
                csrfToken: req.csrfToken()
            });
        }

        const existingProductStmt = db.prepare('SELECT id FROM newarrivals WHERE category = ? OR name = ? OR description = ?');
        let existingProduct;

        // noinspection JSUnresolvedReference
        try {
            existingProduct = existingProductStmt.get(sanitizedCategory, sanitizedName, sanitizedDescription);
        }
        catch (err) {
            handleError(err, res);
        }
        if (existingProduct) {
            deleteFile(icon.path, res);
            return res.status(400).json({
                message: 'Product already exists.',
                error: 'PRODUCT-ALREADY-EXISTS',
                csrfToken: req.csrfToken()
            });
        }

        const imgBase64 = fs.readFileSync(path.extname(icon.path)).toString('base64');
        const ext = path.extname(icon.originalname);

        deleteFile(icon.path, res);

        const stmt = db.prepare('INSERT INTO newarrivals (category, name, description, price, image, imageext) VALUES (?, ?, ?, ?, ?, ?)');
        let info;

        try {
            // noinspection JSUnresolvedReference
            info = stmt.run(sanitizedCategory, sanitizedName, sanitizedDescription, parsedPrice, DOMPurify.sanitize(imgBase64), DOMPurify.sanitize(ext));
        }
        catch (err) {
            handleError(err, res);
        }
        return res.status(200).json({
            message: 'Product Added',
            info: info,
            csrfToken: req.csrfToken()
        });
    }
    else {
        deleteFile(icon.path, res);
        return res.status(400).json({
            message: 'Your Not Supposed To Be Here, Well Lemme Give You A Hint',
            hint: 'It starts with a whisper and ends with a roar and i am CheapPlayz best friend. What am I?',
            csrfToken: req.csrfToken()
        });
    }
});

router.delete('/newarrivals', function(req, res) {
    const authHeader = DOMPurify.sanitize(req.headers['authorization']);

    if (!authHeader) {
        return res.status(401).json({
            message: 'Unauthorized',
            error: 'UNAUTHORIZED',
            csrfToken: req.csrfToken()
        });
    }

    if (authHeader !== keys.keys.deletekey) {
        return res.status(401).json({
            message: 'Unauthorized',
            error: 'UNAUTHORIZED',
            csrfToken: req.csrfToken()
        });
    }
    else if (authHeader === keys.keys.deletekey) {
        const stmt = db.prepare('DROP TABLE newarrivals');
        let result;

        if (!stmt) {
            handleError("STMT ERROR LINE 248 MODULE: newarrivals", res);
        }

        try {
            result = stmt.run();
        }
        catch (err) {
            handleError(err, res);
        }

        return res.status(200).json({
            message: 'Products Deleted',
            result: result,
            csrfToken: req.csrfToken()
        });
    }
});

module.exports = router;