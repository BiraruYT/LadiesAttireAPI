const express = require('express');
const SQLITE3 = require('better-sqlite3');

const router = express.Router();

const dbPath = "./sqlitedb/dev-users.db";
const db = new SQLITE3(dbPath, { verbose: console.log });

router.get('/services/user-to-id', function(req, res) {
    return res.status(400).json({
        message: "Nothing exists here so get out before everything collapses! But if your looking for some services, you can find them here:",
        services: [
            "services/user-to-id:username"
        ],
        error: "NOTHING-EXISTS-HERE"
    });
});

router.get('/services/user-to-id/:username', function(req, res) {
    const username = req.params;

    if (!username) {
        return res.status(400).json({
            message: "You must provide a username.",
            error: "NO-USERNAME-PROVIDED"
        });
    }

    const query = 'SELECT id FROM users WHERE username = ?';

    db.prepare(query, (err, user) => {
        if (err) {
            console.error(err.message);
            return res.status(500).json({
                message: 'Internal Server Error',
                error: err.message
            });
        }

        if (!user) {
            return res.status(400).json({
                message: 'User not found.',
                error: 'USER-NOT-FOUND'
            });
        }

        res.status(200).json({
            message: 'User ID found.',
            userId: user.id
        });
    });
});

module.exports = router;