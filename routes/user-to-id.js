const express = require('express');
const SQLITE3 = require('better-sqlite3');
const { usersDB } = require("../app");

const router = express.Router();

const db = new SQLITE3(usersDB);

router.get('/user-to-id/:username', function(req, res) {
    let username = req.params.username;

    if (typeof username !== 'string') {
        return res.status(400).json({
            message: "Invalid username. Please provide a valid username.",
            error: "INVALID-USERNAME",
            csrfToken: req.csrfToken()
        });
    }

    const stmt = db.prepare('SELECT id FROM users WHERE username = ?');
    const user = stmt.get(username);

    if (user) {
        res.status(200).json({
            message: 'User ID found.',
            userId: user.id,
            csrfToken: req.csrfToken()
        });
    }
    else {
        res.status(400).json({
            message: 'User not found.',
            error: 'USER-NOT-FOUND',
            csrfToken: req.csrfToken()
        });
    }
});

module.exports = router;