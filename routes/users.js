const express = require('express');
const argon2 = require('argon2');
const SQLITE3 = require('better-sqlite3');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);
const crypto = require('crypto');
const utils = require('../js/utils');

const router = express.Router();

const dbPath = "./sqlitedb/dev-users.db";
const db = new SQLITE3(dbPath);

db.pragma('journal_mode = WAL');
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firstname TEXT,
    lastname TEXT,
    username TEXT,
    password TEXT,
    email TEXT,
    icon TEXT
  )
`).run();

/*
db.run(`
  UPDATE users
  SET phone = 'default_value'
  WHERE phone IS NULL
`);
*/

router.get('/users/:id/info', async (req, res) => {
    let id = req.params;
    let body;

    try {
        body = req.body;
    }
    catch (err) {
        return res.status(500).json({
            message: 'Internal Server Error',
            csrfToken: req.csrfToken()
        });
    }

    const parsedId = parseInt(DOMPurify.sanitize(id));
    const isInt = utils.isInt(parsedId);

    if (!isInt) {
        return res.status(400).json({
            message: "User's id isn't a number! Please specify an integer.",
            error: "USER-ID-NOT-INT",
            csrfToken: req.csrfToken()
        });
    }

    const user = db.prepare('SELECT id, firstname, lastname, username, email, password FROM users WHERE id = ?').get(parsedId);

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

    let hashedPassword
    try {
        hashedPassword = await argon2.hash(DOMPurify.sanitize(body.password));
    }
    catch (err) {
        return res.status(500).json({
            message: 'Internal Server Error',
            csrfToken: req.csrfToken()
        });
    }

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

router.post('/users/register', async (req, res) => {
    let body;

    try {
        body = req.body;
    }
    catch (err) {
        return res.status(500).json({
            message: 'Internal Server Error',
            csrfToken: req.csrfToken()
        });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const usernameRegex = /^[a-zA-Z0-9]+$/;
    const spaceRegex = /\s/;

    const { username, password, email } = DOMPurify.sanitize(body);

    if (!username || typeof username !== 'string') {
        return res.status(400).json({
            message: "Invalid or missing user's username.",
            error: "INVALID-USERNAME",
            csrfToken: req.csrfToken()
        });
    }
    else if (!password || typeof password !== 'string') {
        return res.status(400).json({
            message: "Invalid or missing user's password.",
            error: "INVALID-PASSWORD",
            csrfToken: req.csrfToken()
        });
    }
    else if (!email || typeof email !== 'string') {
        return res.status(400).json({
            message: "Invalid or missing user's email.",
            error: "INVALID-EMAIL",
            csrfToken: req.csrfToken()
        });
    }

    if (!spaceRegex.test(username)) {
        return res.status(400).json({
            message: 'Username cannot contain spaces.',
            error: "USERNAME-CONTAINS-SPACES",
            csrfToken: req.csrfToken()
        });
    }
    else if (!spaceRegex.test(password)) {
        return res.status(400).json({
            message: 'Password cannot contain spaces.',
            error: "PASSWORD-CONTAINS-SPACES",
            csrfToken: req.csrfToken()
        });
    }
    else if (!spaceRegex.test(email)) {
        return res.status(400).json({
            message: 'Email cannot contain spaces.',
            error: "EMAIL-CONTAINS-SPACES",
            csrfToken: req.csrfToken()
        });
    }

    if (!usernameRegex.test(username)) {
        return res.status(400).json({
            message: 'Username can only contain letters and numbers.',
            error: "USERNAME-CONTAINS-NON-ALPHANUMERIC-CHARACTERS",
            csrfToken: req.csrfToken()
        });
    }
    else if (!emailRegex.test(email)) {
        return res.status(400).json({
            message: 'Invalid email format.',
            error: "INVALID-EMAIL-FORMAT",
            csrfToken: req.csrfToken()
        });
    }

    if (username.length > 15) {
        return res.status(400).json({
            message: 'Username exceeds the maximum length of 15 characters.',
            error: "USERNAME-TOO-LONG",
            csrfToken: req.csrfToken()
        });
    }
    else if (password.length > 30) {
        return res.status(400).json({
            message: 'Password exceeds the maximum length of 30 characters.',
            error: "PASSWORD-TOO-LONG",
            csrfToken: req.csrfToken()
        });
    }
    else if (email.length > 40) {
        return res.status(400).json({
            message: 'Email exceeds the maximum length of 40 characters.',
            error: "EMAIL-TOO-LONG",
            csrfToken: req.csrfToken()
        });
    }

    let argon2HashedPassword

    try {
        argon2HashedPassword = await argon2.hash(DOMPurify.sanitize(body.password, crypto.randomBytes(32)));
    }
    catch (err) {
        return res.status(500).json({
            message: 'Internal Server Error',
            csrfToken: req.csrfToken()
        });
    }

    const newUser = {
        username: DOMPurify.sanitize(body.username),
        password: DOMPurify.sanitize(argon2HashedPassword),
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

        const stmt = db.prepare('INSERT INTO users (username, password, email) VALUES (?, ?, ?)');
        const result = stmt.run(DOMPurify.sanitize(newUser.username), DOMPurify.sanitize(newUser.password), DOMPurify.sanitize(newUser.email));

        console.log(`A new user has been added with ID ${result.id}`);
        return res.status(200).json({
            message: 'User successfully added.',
            newUser: {
                id: result.id,
                username: newUser.username,
                email: newUser.email
            },
            csrfToken: req.csrfToken()
        });
    } catch (error) {
        return res.status(500).json({
            message: 'Internal Server Error',
            csrfToken: req.csrfToken()
        });
    }
});

router.post('/users/:id/edit', async (req, res) => {
    let id = req.params;
    let body;

    try {
        body = req.body;
    }
    catch (err) {
        return res.status(500).json({
            message: 'Internal Server Error',
            csrfToken: req.csrfToken()
        });
    }

    const noUserIdProvided = {
        message: "No user's id? Please specify!",
        error: "NO-USER-ID",
        csrfToken: req.csrfToken()
    };

    try {
        id = DOMPurify.sanitize(body.id);
    }
    catch (err) {
        return res.status(400).json(noUserIdProvided);
    }

    if (!id) {
        return res.status(400).json(noUserIdProvided);
    } else if (!body) {
        return res.status(400).json({
            message: "No user's info? Please specify!",
            error: "NO-USER-INFO",
            csrfToken: req.csrfToken()
        });
    }

    const parsedId = parseInt(DOMPurify.sanitize(id));
    const isInt = utils.isInt(parsedId);

    if (!isInt) {
        return res.status(400).json({
            message: "User's id isn't a number! Please specify an integer.",
            error: "USER-ID-NOT-INT",
            csrfToken: req.csrfToken()
        });
    }

    const noPasswordProvided = {
        message: "No user's password? Please specify!",
        error: "NO-USER-PASSWORD",
        csrfToken: req.csrfToken()
    };

    let normalpassword

    try {
        normalpassword = DOMPurify.sanitize(body.password);
    }
    catch (err) {
        return res.status(400).json(noPasswordProvided);
    }

    if (!normalpassword) {
        return res.status(400).json(noPasswordProvided);
    }

    const user = db.prepare('SELECT password FROM users WHERE id = ?').get(parsedId);

    if (!user) {
        return res.status(400).json({
            message: `User with ID ${parsedId} not found.`,
            error: "USER-NOT-FOUND",
            csrfToken: req.csrfToken()
        });
    }

    let isPasswordMatch

    try {
        isPasswordMatch = await argon2.verify(user.password, normalpassword);
    } catch (err) {
        return res.status(500).json({
            message: 'Internal Server Error',
            csrfToken: req.csrfToken()
        });
    }

    if (!isPasswordMatch) {
        return res.status(400).json({
            message: "Password doesn't match the user's password.",
            error: "PASSWORD-MISMATCH",
            csrfToken: req.csrfToken()
        });
    }

    const noFieldsProvided = {
        message: `No fields provided for update. Please specify at least one field "update" {"username": "test", "password": "testpass", "email": "test@gmail.com"}.`,
        error: "NO-FIELDS-FOR-UPDATE",
        csrfToken: req.csrfToken()
    }

    try {
        if (!body.update && !body.update.username && !body.update.password && !body.update.email) {
            return res.status(400).json(noFieldsProvided);
        }
    }
    catch (err) {
        console.log(err)
        return res.status(400).json(noFieldsProvided);
    }

    const updateFields = [];
    const values = [];

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const usernameRegex = /^[a-zA-Z0-9]+$/;
    const spaceRegex = /\s/;

    if (body.update.username) {
        if (!body.update.username || typeof body.update.username !== 'string') {
            return res.status(400).json({
                message: "Invalid or missing user's username.",
                error: "INVALID-USERNAME",
                csrfToken: req.csrfToken()
            });
        }
        if (!spaceRegex.test(body.update.username)) {
            return res.status(400).json({
                message: 'Username cannot contain spaces.',
                error: "USERNAME-CONTAINS-SPACES",
                csrfToken: req.csrfToken()
            });
        }
        if (!usernameRegex.test(body.update.username)) {
            return res.status(400).json({
                message: 'Username can only contain letters and numbers.',
                error: "USERNAME-CONTAINS-NON-ALPHANUMERIC-CHARACTERS",
                csrfToken: req.csrfToken()
            });
        }
        if (body.update.username.length > 15) {
            return res.status(400).json({
                message: 'Username exceeds the maximum length of 15 characters.',
                error: "USERNAME-TOO-LONG",
                csrfToken: req.csrfToken()
            });
        }
        updateFields.push('username = ?');
        values.push(DOMPurify.sanitize(body.update.username));
    }
    if (body.update.password) {
        if (!body.update.password || typeof body.update.password !== 'string') {
            return res.status(400).json({
                message: "Invalid or missing user's password.",
                error: "INVALID-PASSWORD",
                csrfToken: req.csrfToken()
            });
        }
        if (!spaceRegex.test(body.update.password)) {
            return res.status(400).json({
                message: 'Password cannot contain spaces.',
                error: "PASSWORD-CONTAINS-SPACES",
                csrfToken: req.csrfToken()
            });
        }
        if (body.update.password.length > 30) {
            return res.status(400).json({
                message: 'Password exceeds the maximum length of 30 characters.',
                error: "PASSWORD-TOO-LONG",
                csrfToken: req.csrfToken()
            });
        }

        let hashedPassword
        try {
            hashedPassword = await argon2.hash(DOMPurify.sanitize(body.update.password));
        }
        catch (err) {
            return res.status(500).json({
                message: 'Internal Server Error',
                csrfToken: req.csrfToken()
            });
        }
        updateFields.push('password = ?');
        values.push(hashedPassword);
    }
    if (body.update.email) {
        if (!body.update.email || typeof body.update.email !== 'string') {
            return res.status(400).json({
                message: "Invalid or missing user's email.",
                error: "INVALID-EMAIL",
                csrfToken: req.csrfToken()
            });
        }
        if (!spaceRegex.test(body.update.email)) {
            return res.status(400).json({
                message: 'Email cannot contain spaces.',
                error: "EMAIL-CONTAINS-SPACES",
                csrfToken: req.csrfToken()
            });
        }
        if (!emailRegex.test(body.update.email)) {
            return res.status(400).json({
                message: 'Invalid email format.',
                error: "INVALID-EMAIL-FORMAT",
                csrfToken: req.csrfToken()
            });
        }
        if (body.update.email.length > 40) {
            return res.status(400).json({
                message: 'Email exceeds the maximum length of 40 characters.',
                error: "EMAIL-TOO-LONG",
                csrfToken: req.csrfToken()
            });
        }

        updateFields.push('email = ?');
        values.push(DOMPurify.sanitize(body.update.email));
    }

    const stmt = db.prepare(`UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`)
    const result = stmt.run([...values, parsedId]);

    if (result.changes > 0) {
        const updatedUser = db.prepare('SELECT id, username, email FROM users WHERE id = ?').get(parsedId);

        console.log(`User with ID ${parsedId} has been updated.`);
        return res.status(200).json({
            message: 'User successfully updated.',
            updatedUser: updatedUser,
            csrfToken: req.csrfToken()
        });
    }
    else {
        return res.status(400).json({
            message: `User with ID ${parsedId} not found.`,
            error: "USER-NOT-FOUND",
            csrfToken: req.csrfToken()
        });
    }
});

module.exports = router;