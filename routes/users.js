const express = require('express');
const argon2 = require('argon2');
const SQLITE3 = require('better-sqlite3');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);
const utils = require('../js/utils');

const router = express.Router();

const dbPath = "./sqlitedb/dev-users.db";
const db = new SQLITE3(dbPath, { verbose: console.log });

db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    email TEXT
  )
`).run();

/*
db.run(`
  UPDATE users
  SET phone = 'default_value'
  WHERE phone IS NULL
`);
*/

router.post('/users', async (req, res) => {
    const { body } = req;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!body || typeof body !== 'object') {
        return res.status(400).json({
            message: "Invalid request body. Please provide user's info.",
            error: "INVALID-REQUEST-BODY",
            csrfToken: req.csrfToken()
        });
    }

    const { username, password, email } = body;

    if (!username || typeof username !== 'string') {
        return res.status(400).json({
            message: "Invalid or missing user's username.",
            error: "INVALID-USERNAME",
            csrfToken: req.csrfToken()
        });
    } else if (!password || typeof password !== 'string') {
        return res.status(400).json({
            message: "Invalid or missing user's password.",
            error: "INVALID-PASSWORD",
            csrfToken: req.csrfToken()
        });
    } else if (!email || typeof email !== 'string') {
        return res.status(400).json({
            message: "Invalid or missing user's email.",
            error: "INVALID-EMAIL",
            csrfToken: req.csrfToken()
        });
    }

    if (!emailRegex.test(email)) {
        return res.status(400).json({
            isValid: false,
            message: 'Invalid email format.',
            error: "INVALID-EMAIL-FORMAT",
            csrfToken: req.csrfToken()
        });
    }

    if (email.length > 40) {
        return res.status(400).json({
            isValid: false,
            message: 'Email exceeds the maximum length of 40 characters.',
            error: "EMAIL-TOO-LONG",
            csrfToken: req.csrfToken()
        });
    }
    if (username.length > 15) {
        return res.status(400).json({
            isValid: false,
            message: 'Username exceeds the maximum length of 15 characters.',
            error: "USERNAME-TOO-LONG",
            csrfToken: req.csrfToken()
        });
    }
    if (password.length > 30) {
        return res.status(400).json({
            isValid: false,
            message: 'Password exceeds the maximum length of 30 characters.',
            error: "PASSWORD-TOO-LONG",
            csrfToken: req.csrfToken()
        });
    }

    const newUser = {
        username: DOMPurify.sanitize(body.username),
        password: await argon2.hash(DOMPurify.sanitize(body.password)),
        email: DOMPurify.sanitize(body.email),
    };

    try {
        const existingUser = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(newUser.username, newUser.email);

        if (existingUser) {
            return res.status(400).json({
                message: 'User with the same username or email already exists.',
                error: 'USER-ALREADY-EXISTS',
                existingUserId: existingUser.id,
                csrfToken: req.csrfToken()
            });
        }

        const { lastInsertRowid } = db.prepare('INSERT INTO users (username, password, email) VALUES (?, ?, ?)').run(newUser.username, newUser.password, newUser.email);

        console.log(`A new user has been added with ID ${lastInsertRowid}`);
        return res.status(200).json({
            message: 'User successfully added.',
            newUser: {
                id: lastInsertRowid,
                username: newUser.username,
                email: newUser.email
            },
            csrfToken: req.csrfToken()
        });
    } catch (error) {
        console.error(`Error executing SQL: ${error.message}`);
        return res.status(500).json({
            message: 'Internal Server Error',
            error: error.message,
            csrfToken: req.csrfToken()
        });
    }
});

router.get('/users/:id', async (req, res) => {
    const { id } = req.params;
    const { body } = req;

    if (!id) {
        return res.status(400).json({
            message: "No user's id? Please specify!",
            error: "NO-USER-ID",
            csrfToken: req.csrfToken()
        });
    }

    const parsedId = parseInt(id);
    const isInt = utils.isInt(parsedId);

    if (!isInt) {
        return res.status(400).json({
            message: "User's id isn't a number! Please specify an integer.",
            error: "USER-ID-NOT-INT",
            csrfToken: req.csrfToken()
        });
    }

    const user = db.prepare('SELECT id, username, email, password FROM users WHERE id = ?').get(parsedId);

    if (!user) {
        return res.status(400).json({
            message: `User with ID ${parsedId} not found.`,
            error: "USER-NOT-FOUND",
            csrfToken: req.csrfToken()
        });
    }

    if (!utils.isInt(parsedId)) {
        return res.status(400).json({
            message: "User's id isn't a number! Please specify an integer.",
            error: "USER-ID-NOT-INT",
            csrfToken: req.csrfToken()
        });
    }

    const hashedPassword = await argon2.hash(body.password);

    if (hashedPassword === user.password) {
        return res.status(200).json({
            message: 'User successfully found.',
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            },
            csrfToken: req.csrfToken()
        });
    } else {
        return res.status(200).json({
            message: 'User successfully found',
            user: {
                id: user.id,
                username: user.username
            },
            csrfToken: req.csrfToken()
        });
    }

});

router.post('/users/:id', async (req, res) => {
    const { id } = req.params;
    const { body } = req;

    if (!id) {
        return res.status(400).json({
            message: "No user's id? Please specify!",
            error: "NO-USER-ID",
            csrfToken: req.csrfToken()
        });
    } else if (!body) {
        return res.status(400).json({
            message: "No user's info? Please specify!",
            error: "NO-USER-INFO",
            csrfToken: req.csrfToken()
        });
    }

    const parsedId = parseInt(id);
    const isInt = utils.isInt(parsedId);

    if (!isInt) {
        return res.status(400).json({
            message: "User's id isn't a number! Please specify an integer.",
            error: "USER-ID-NOT-INT",
            csrfToken: req.csrfToken()
        });
    }

    if (!body.username && !body.password && !body.email) {
        return res.status(400).json({
            message: "No fields provided for update. Please specify at least one field (username, password, email).",
            error: "NO-FIELDS-FOR-UPDATE",
            csrfToken: req.csrfToken()
        });
    }

    try {
        const user = db.prepare('SELECT password FROM users WHERE id = ?').get(parsedId);

        if (!user) {
            return res.status(400).json({
                message: `User with ID ${parsedId} not found.`,
                error: "USER-NOT-FOUND",
                csrfToken: req.csrfToken()
            });
        }

        const isPasswordMatch = await argon2.verify(user.password, body.password);

        if (!isPasswordMatch) {
            return res.status(400).json({
                message: "Password doesn't match the stored password.",
                error: "PASSWORD-MISMATCH",
                csrfToken: req.csrfToken()
            });
        }

        const updateFields = [];
        const values = [];

        if (body.username) {
            updateFields.push('username = ?');
            values.push(DOMPurify.sanitize(body.username));
        }
        if (body.password) {
            const hashedPassword = await argon2.hash(DOMPurify.sanitize(body.password));
            updateFields.push('password = ?');
            values.push(hashedPassword);
        }
        if (body.email) {
            updateFields.push('email = ?');
            values.push(DOMPurify.sanitize(body.email));
        }

        db.prepare(`UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`)
            .run([...values, parsedId], async function (err) {
                if (err) {
                    console.error(`Error executing SQL: ${err.message}`);
                    return res.status(500).json({
                        message: 'Internal Server Error',
                        error: err.message,
                        csrfToken: req.csrfToken()
                    });
                }

                console.log(`User with ID ${parsedId} has been updated.`);
                return res.status(400).json({
                    message: 'User successfully updated.',
                    updatedUser: {
                        id: parsedId,
                        username: body.username
                    },
                    csrfToken: req.csrfToken()
                });
            });
    } catch (err) {
        console.error(err.message);
        return res.status(500).json({
            message: 'Internal Server Error',
            error: err.message,
            csrfToken: req.csrfToken()
        });
    }
});

module.exports = router;