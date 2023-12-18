const express = require('express');
const bcrypt = require('bcrypt');
const SQLITE3 = require('better-sqlite3');
const { Webhook, MessageBuilder } = require('discord-webhook-node');
const utils = require('../js/utils');

const router = express.Router();

const dbPath = "./sqlitedb/dev-users.db";
const db = new SQLITE3(dbPath, { verbose: console.log });

const WEBHOOK_IMAGE_URL = 'https://cdn.discordapp.com/attachments/1185844013119590402/1185848513377079317/Ladies_Attire.png?ex=65911a7d&is=657ea57d&hm=f2bbc56b0fbe985928c61d917f72a2ca9a7507872598a64ddb8b93a197718cbf&';
const usersPostWebhook = new Webhook("https://discord.com/api/webhooks/1185846005242015855/c3Ap19znWx8YmzMNp1_H-IDKDD1_W4n1ZkmEF_01BSpYeNjmsI7cXgIDZ0PNGRuLgHYR");
const usersIdGetWebhook = new Webhook("https://discord.com/api/webhooks/1185846170212372570/wVH5kD4mOmvEHZCiCo58oJmPf7Njeoo4asJ01jZqVbMnaVNVvYqR8dgKeyab9p-PhPaB");
const usersIdPostWebhook = new Webhook("https://discord.com/api/webhooks/1185871628870111332/QLL6qJPLOul2J3OCBrr2iuMA_sVFLoXpQjpOjKddO-Z6GewKy0wZK5CKkn6wim5sXx-q");

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

function setupWebHooks() {
    usersPostWebhook.setUsername('Server Info');
    usersIdGetWebhook.setUsername('Server Info');
    usersIdPostWebhook.setUsername('Server Info');

    usersPostWebhook.setAvatar(WEBHOOK_IMAGE_URL);
    usersIdGetWebhook.setAvatar(WEBHOOK_IMAGE_URL);
    usersIdPostWebhook.setAvatar(WEBHOOK_IMAGE_URL);

    usersPostWebhook.send('Server is online.');
    usersIdGetWebhook.send('Server is online.');
    usersIdPostWebhook.send('Server is online.');
}

setupWebHooks();

router.get('/users', async (req, res) => {
    return res.status(400).json({
        message: "Nothing exists here so get out before everything collapses!",
        error: "NOTHING-EXISTS-HERE",
        csrfToken: req.csrfToken()
    });
});

router.post('/users', async (req, res) => {
    const { body } = req;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const userIp = req.ipInfo.ip;
    const userAgent = req.headers['user-agent'];
    const forwardedFor = req.headers['x-forwarded-for'];
    const language = req.headers['accept-language'];

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
        username: body.username,
        password: await bcrypt.hash(body.password, 10),
        email: body.email
    };

    try {
        const existingUser = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(newUser.username, newUser.email);

        if (existingUser) {
            await usersPostWebhook.send(new MessageBuilder()
                .setTitle(`Existing User: ${existingUser.id}`)
                .setColor('#FA00FF')
                .setDescription(`
                    Users IP: ${userIp}
                    User Agent: ${userAgent}
                    Forwarded For: ${forwardedFor}
                    Language: ${language}
                `));

            return res.status(400).json({
                message: 'User with the same username or email already exists.',
                error: 'USER-ALREADY-EXISTS',
                existingUserId: existingUser.id,
                csrfToken: req.csrfToken()
            });
        }

        const { lastInsertRowid } = db.prepare('INSERT INTO users (username, password, email) VALUES (?, ?, ?)').run(newUser.username, newUser.password, newUser.email);

        await usersPostWebhook.send(new MessageBuilder()
            .setTitle(`User Created: ${lastInsertRowid}`)
            .setColor('#FA00FF')
            .setDescription(`
                Users IP: ${userIp}
                User Agent: ${userAgent}
                Forwarded For: ${forwardedFor}
                Language: ${language}
            `));

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
        await usersPostWebhook.send(new MessageBuilder()
            .setTitle(`Error Code: ${error.message}`)
            .setColor('#FA00FF')
            .setDescription(`
                Users IP: ${userIp}
                User Agent: ${userAgent}
                Forwarded For: ${forwardedFor}
                Language: ${language}
            `));

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
    const userIp = req.ipInfo.ip;
    const userAgent = req.headers['user-agent'];
    const forwardedFor = req.headers['x-forwarded-for'];
    const language = req.headers['accept-language'];

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

    try {
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

        const hashedPassword = await bcrypt.hash(req.query.password, 10);

        if (hashedPassword === user.password) {
            await usersIdGetWebhook.send(new MessageBuilder()
                .setTitle(`Sent User: ${user.id}`)
                .setColor('#FA00FF')
                .setDescription(`
                    Users IP: ${userIp}
                    User Agent: ${userAgent}
                    Forwarded For: ${forwardedFor}
                    Language: ${language}
                `));

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
            await usersIdGetWebhook.send(new MessageBuilder()
                .setTitle(`Sent User: ${user.id}`)
                .setColor('#FA00FF')
                .setDescription(`
                    Users IP: ${userIp}
                    User Agent: ${userAgent}
                    Forwarded For: ${forwardedFor}
                    Language: ${language}
                `));

            return res.status(400).json({
                message: 'Invalid password.',
                error: "INVALID-PASSWORD",
                csrfToken: req.csrfToken()
            });
        }
    } catch (err) {
        await usersIdGetWebhook.send(new MessageBuilder()
            .setTitle(`Error Code: ${err.message}`)
            .setColor('#FA00FF')
            .setDescription(`
                Users IP: ${userIp}
                User Agent: ${userAgent}
                Forwarded For: ${forwardedFor}
                Language: ${language}
            `));

        console.error(err.message);
        return res.status(500).json({
            message: 'Internal Server Error',
            error: err.message,
            csrfToken: req.csrfToken()
        });
    }
});

router.post('/users/:id', async (req, res) => {
    const { id } = req.params;
    const { body } = req;
    const userIp = req.ipInfo.ip;
    const userAgent = req.headers['user-agent'];
    const forwardedFor = req.headers['x-forwarded-for'];
    const language = req.headers['accept-language'];

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

        const isPasswordMatch = await bcrypt.compare(body.password, user.password);

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
            values.push(body.username);
        }
        if (body.password) {
            const hashedPassword = await bcrypt.hash(body.password, 10);
            updateFields.push('password = ?');
            values.push(hashedPassword);
        }
        if (body.email) {
            updateFields.push('email = ?');
            values.push(body.email);
        }

        db.prepare(`UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`, [...values, parsedId], async function (err) {
            if (err) {
                try {
                    await usersIdPostWebhook.send(new MessageBuilder()
                        .setTitle(`Error Code: ${err.message}`)
                        .setColor('#FA00FF')
                        .setDescription(`
                            Users IP: ${userIp}
                            User Agent: ${userAgent}
                            Forwarded For: ${forwardedFor}
                            Language: ${language}
                        `));

                    console.error(`Error executing SQL: ${err.message}`);
                    return res.status(500).json({
                        message: 'Internal Server Error',
                        error: err.message,
                        csrfToken: req.csrfToken()
                    });
                } catch (error) {
                    console.error('Error sending message to Discord:', error.message);
                }
            }

            try {
                await usersIdPostWebhook.send(new MessageBuilder()
                    .setTitle(`User Updated: ${parsedId}`)
                    .setColor('#FA00FF')
                    .setDescription(`
                        Users IP: ${userIp}
                        User Agent: ${userAgent}
                        Forwarded For: ${forwardedFor}
                        Language: ${language}
                    `));

                console.log(`User with ID ${parsedId} has been updated.`);
                return res.status(400).json({
                    message: 'User successfully updated.',
                    updatedUser: {
                        id: parsedId,
                        username: body.username
                    },
                    csrfToken: req.csrfToken()
                });
            } catch (error) {
                console.error('Error sending message to Discord:', error.message);
                return res.status(500).json({
                    error: 'Internal Server Error',
                    csrfToken: req.csrfToken()
                });
            }
        }).run();
    } catch (err) {
        try {
            await usersIdPostWebhook.send(new MessageBuilder()
                .setTitle(`Error Code: ${err.message}`)
                .setColor('#FA00FF')
                .setDescription(`
                    Users IP: ${userIp}
                    User Agent: ${userAgent}
                    Forwarded For: ${forwardedFor}
                    Language: ${language}
                `));

            console.error(err.message);
            return res.status(500).json({
                message: 'Internal Server Error',
                error: err.message,
                csrfToken: req.csrfToken()
            });
        } catch (error) {
            console.error('Error sending message to Discord:', error.message);
            return res.status(500).json({
                error: 'Internal Server Error',
                csrfToken: req.csrfToken()
            });
        }
    }
});

module.exports = router;