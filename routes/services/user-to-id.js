const express = require('express');
const SQLITE3 = require('better-sqlite3');

const router = express.Router();

const dbPath = "./sqlitedb/dev-users.db";
const db = new SQLITE3(dbPath, { verbose: console.log });

router.get('/services/user-to-id/:username', function(req, res) {
    const username = req.params;

    if (!username) {
        return res.status(400).json({
            message: "You must provide a username.",
            error: "NO-USERNAME-PROVIDED",
            csrfToken: req.csrfToken()
        });
    }

    const query = 'SELECT id FROM users WHERE username = ?';

    db.prepare(query, (err, user) => {
        if (err) {
            console.error(err.message);
            return res.status(500).json({
                message: 'Internal Server Error',
                error: err.message,
                csrfToken: req.csrfToken()
            });
        }

        if (!user) {
            return res.status(400).json({
                message: 'User not found.',
                error: 'USER-NOT-FOUND',
                csrfToken: req.csrfToken()
            });
        }

        res.status(200).json({
            message: 'User ID found.',
            userId: user.id,
            csrfToken: req.csrfToken()
        });
    });
});

module.exports = router;