const express = require('express');
const sqlite3 = require('sqlite3');
const utils = require('../js/utils.js');

const router = express.Router();

const dbPath = "./sqlitedb/dev-users.db";
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error(err.message + ", On module Users.");
    } else {
        console.log('Connected to the SQLite database on module User-To-ID.');
    }
});

router.get('/services/user-to-id/:username', function(req, res) {
    const username = req.params.username;

    if (!username) {
        return res.status(400).json({
            message: "You must provide a username.",
            error: "NO-USERNAME-PROVIDED"
        });
    }

    const query = 'SELECT id FROM users WHERE username = ?';

    db.get(query, [username], (err, user) => {
        if (err) {
            console.error(err.message);
            return res.status(500).json({
                message: 'Internal Server Error',
                error: err.message
            });
        }

        if (!user) {
            return res.status(404).json({
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