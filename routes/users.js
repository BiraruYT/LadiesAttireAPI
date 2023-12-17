const express = require('express');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3');
const { Webhook, MessageBuilder } = require('discord-webhook-node');
const utils = require('../js/utils.js');

const router = express.Router();

const dbPath = "./sqlitedb/dev-users.db";
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error(err.message + ", On module Users.");
    } else {
        console.log('Connected to the SQLite database on module Users.');
    }
});

const WEBHOOK_IMAGE_URL = 'https://cdn.discordapp.com/attachments/1185844013119590402/1185848513377079317/Ladies_Attire.png?ex=65911a7d&is=657ea57d&hm=f2bbc56b0fbe985928c61d917f72a2ca9a7507872598a64ddb8b93a197718cbf&';
const usersGetWebhook = new Webhook("https://discord.com/api/webhooks/1185845660273090640/ak4x7X9um1cX6KvDchNMQjmSmQ_eu2dW-VMrjlEK9m6zYlMUpNYQPV5I4Yzod4f161wH");
const usersPostWebhook = new Webhook("https://discord.com/api/webhooks/1185846005242015855/c3Ap19znWx8YmzMNp1_H-IDKDD1_W4n1ZkmEF_01BSpYeNjmsI7cXgIDZ0PNGRuLgHYR");
const usersIdGetWebhook = new Webhook("https://discord.com/api/webhooks/1185846170212372570/wVH5kD4mOmvEHZCiCo58oJmPf7Njeoo4asJ01jZqVbMnaVNVvYqR8dgKeyab9p-PhPaB");
const usersIdPostWebhook = new Webhook("https://discord.com/api/webhooks/1185871628870111332/QLL6qJPLOul2J3OCBrr2iuMA_sVFLoXpQjpOjKddO-Z6GewKy0wZK5CKkn6wim5sXx-q");

db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    email TEXT
  )
`);

/*
db.run(`
  UPDATE users
  SET phone = 'default_value'
  WHERE phone IS NULL
`);
*/

function setupWebHooks() {
    usersGetWebhook.setUsername('Server Info');
    usersPostWebhook.setUsername('Server Info');
    usersIdGetWebhook.setUsername('Server Info');
    usersIdPostWebhook.setUsername('Server Info');

    usersGetWebhook.setAvatar(WEBHOOK_IMAGE_URL);
    usersPostWebhook.setAvatar(WEBHOOK_IMAGE_URL);
    usersIdGetWebhook.setAvatar(WEBHOOK_IMAGE_URL);
    usersIdPostWebhook.setAvatar(WEBHOOK_IMAGE_URL);

    usersGetWebhook.send('Server is online.')
    usersPostWebhook.send('Server is online.')
    usersIdGetWebhook.send('Server is online.')
    usersIdPostWebhook.send('Server is online.')
}

setupWebHooks();

router.get('/users', async (req, res) => {
    const userIp = req.ipInfo.ip;
    const userAgent = req.headers['user-agent'];
    const forwardedFor = req.headers['x-forwarded-for'];
    const language = req.headers['accept-language'];

    try {
        await usersGetWebhook.send(new MessageBuilder()
            .setTitle('Nothing Exists Here')
            .setColor('#FA00FF')
            .setDescription(`
                Users IP: ${userIp}
                User Agent: ${userAgent}
                Forwarded For: ${forwardedFor}
                Language: ${language}
            `))

        return res.status(200).json({
            message: "Nothing exists here so get out before everything collapses!",
            error: "NOTHING-EXISTS-HERE"
        });
    } catch (error) {
        console.error('Error sending message to Discord:', error.message);
    }
});

router.post('/users', async(req, res) => {
    const {body} = req;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const userIp = req.ipInfo.ip;
    const userAgent = req.headers['user-agent'];
    const forwardedFor = req.headers['x-forwarded-for'];
    const language = req.headers['accept-language'];

    if (!body) {
        return res.status(400).json({
            message: "No user's info? Please specify!",
            error: "NO-USER-INFO"
        });
    }
    if (!body.username) {
        return res.status(400).json({
            message: "No user's username? Please specify!",
            error: "NO-USER-USERNAME"
        });
    } else if (!body.password) {
        return res.status(400).json({
            message: "No user's password? Please specify!",
            error: "NO-USER-PASSWORD"
        });
    } else if (!body.email) {
        return res.status(400).json({
            message: "No user's email? Please specify!",
            error: "NO-USER-EMAIL"
        });
    }

    if (!emailRegex.test(body.email)) {
        return res.status(400).json({
            isValid: false,
            message: 'Invalid email format.',
            error: "INVALID-EMAIL-FORMAT"
        });
    }

    if (body.email.length > 40) {
        return res.status(400).json({
            isValid: false,
            message: 'Email exceeds the maximum length of 40 characters.',
            error: "EMAIL-TOO-LONG"
        });
    }
    if (body.username.length > 15) {
        return res.status(400).json({
            isValid: false,
            message: 'Username exceeds the maximum length of 15 characters.',
            error: "USERNAME-TOO-LONG"
        });
    }
    if (body.password.length > 30) {
        return res.status(400).json({
            isValid: false,
            message: 'Password exceeds the maximum length of 30 characters.',
            error: "PASSWORD-TOO-LONG"
        });
    }

    const newUser = {
        username: body.username,
        password: await bcrypt.hash(body.password, 10),
        email: body.email
    };

    db.get('SELECT id FROM users WHERE username = ? OR email = ?', [newUser.username, newUser.email], (err, existingUser) => {
        if (err) {
            try {
                usersPostWebhook.send(new MessageBuilder()
                    .setTitle(`Error Code: ${err.message}`)
                    .setColor('#FA00FF')
                    .setDescription(`
                        Users IP: ${userIp}
                        User Agent: ${userAgent}
                        Forwarded For: ${forwardedFor}
                        Language: ${language}
                    `))

                console.error(`Error Loading SQL: ${err.message}`);
                return res.status(500).json({
                    message: 'Internal Server Error',
                    error: err.message
                });
            } catch (error) {
                console.error('Error sending message to Discord:', error.message);
                return res.status(500).json({ error: 'Internal Server Error' });
            }
        }

        if (existingUser) {
            try {
                usersPostWebhook.send(new MessageBuilder()
                    .setTitle(`Existing User: ${existingUser.id}`)
                    .setColor('#FA00FF')
                    .setDescription(`
                        Users IP: ${userIp}
                        User Agent: ${userAgent}
                        Forwarded For: ${forwardedFor}
                        Language: ${language}
                    `))

                return res.status(400).json({
                    message: 'User with the same username or email already exists.',
                    error: 'USER-ALREADY-EXISTS',
                    existingUserId: existingUser.id
                });
            } catch (error) {
                console.error('Error sending message to Discord:', error.message);
                return res.status(500).json({ error: 'Internal Server Error' });
            }
        } else {
            db.run('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', [newUser.username, newUser.password, newUser.email], function (err) {
                if (err) {
                    try {
                        usersPostWebhook.send(new MessageBuilder()
                            .setTitle(`Error Code: ${err.message}`)
                            .setColor('#FA00FF')
                            .setDescription(`
                                Users IP: ${userIp}
                                User Agent: ${userAgent}
                                Forwarded For: ${forwardedFor}
                                Language: ${language}
                            `))

                        console.error(`Error executing SQL: ${this.error}`);
                        console.error(`Error executing SQL: ${err.message}`);
                        res.status(500).json({
                            message: 'Internal Server Error',
                            error: err.message
                        });
                    } catch (error) {
                        console.error('Error sending message to Discord:', error.message);
                    }
                    return;
                }
                try {
                    usersPostWebhook.send(new MessageBuilder()
                        .setTitle(`User Created: ${this.lastID}`)
                        .setColor('#FA00FF')
                        .setDescription(`
                            Users IP: ${userIp}
                            User Agent: ${userAgent}
                            Forwarded For: ${forwardedFor}
                            Language: ${language}
                        `))

                    console.log(`A new user has been added with ID ${this.lastID}`);
                    return res.status(200).json({
                        message: 'User successfully added.',
                        newUser: {
                            id: this.lastID,
                            username: newUser.username,
                            email: newUser.email
                        }
                    });
                } catch (error) {
                    console.error('Error sending message to Discord:', error.message);
                    return res.status(500).json({ error: 'Internal Server Error' });
                }
            });
        }
    });
});

router.get('/users/:id', (req, res) => {
    const { id } = req.params;
    const { body } = req;
    const userIp = req.ipInfo.ip;
    const userAgent = req.headers['user-agent'];
    const forwardedFor = req.headers['x-forwarded-for'];
    const language = req.headers['accept-language'];

    if (!id) {
        return res.status(400).json({
            message: "No user's id? Please specify!",
            error: "NO-USER-ID"
        });
    }
    else if (!body) {
        return res.status(400).json({
            message: "No user's info? Please specify!",
            error: "NO-USER-INFO"
        });
    }

    const parsedId = parseInt(id);
    const isInt = utils.isInt(parsedId);

    if (!isInt) {
        return res.status(400).json({
            message: "User's id isn't a number! Please specify an integer.",
            error: "USER-ID-NOT-INT"
        });
    }

    db.get('SELECT id, username, email, password FROM users WHERE id = ?', [parsedId], async (err, user) => {
        if (err) {
            try {
                await usersIdGetWebhook.send(new MessageBuilder()
                    .setTitle(`Error Code: ${err.message}`)
                    .setColor('#FA00FF')
                    .setDescription(`
                        Users IP: ${userIp}
                        User Agent: ${userAgent}
                        Forwarded For: ${forwardedFor}
                        Language: ${language}
                    `))

                console.error(err.message);
                return res.status(500).json({
                    message: 'Internal Server Error',
                    error: err.message
                });
            } catch (error) {
                console.error('Error sending message to Discord:', error.message);
            }
        }

        if (!user) {
            return res.status(400).json({
                message: `User with ID ${parsedId} not found.`,
                error: "USER-NOT-FOUND"
            });
        } else {
            const isPasswordHashed = user.password.startsWith('$2b$');

            if (isPasswordHashed) {
                const isPasswordMatch = await bcrypt.compare(body.password, user.password);

                if (isPasswordMatch) {
                    try {
                        await usersIdGetWebhook.send(new MessageBuilder()
                            .setTitle(`Sent User: ${user.id}`)
                            .setColor('#FA00FF')
                            .setDescription(`
                                Users IP: ${userIp}
                                User Agent: ${userAgent}
                                Forwarded For: ${forwardedFor}
                                Language: ${language}
                            `))

                        return res.status(200).json({
                            message: 'User successfully found.',
                            user: {
                                id: user.id,
                                username: user.username,
                                email: user.email
                            }
                        });
                    } catch (error) {
                        console.error('Error sending message to Discord:', error.message);
                    }
                } else {
                    try {
                        await usersIdGetWebhook.send(new MessageBuilder()
                            .setTitle(`Sent User: ${user.id}`)
                            .setColor('#FA00FF')
                            .setDescription(`
                                Users IP: ${userIp}
                                User Agent: ${userAgent}
                                Forwarded For: ${forwardedFor}
                                Language: ${language}
                            `))

                        return res.status(200).json({
                            message: 'User successfully found.',
                            user: {
                                id: user.id,
                                username: user.username
                            }
                        });
                    } catch (error) {
                        console.error('Error sending message to Discord:', error.message);
                    }
                }
            } else {
                if (body.password === user.password) {
                    try {
                        await usersIdGetWebhook.send(new MessageBuilder()
                            .setTitle(`Sent User: ${user.id}`)
                            .setColor('#FA00FF')
                            .setDescription(`
                                Users IP: ${userIp}
                                User Agent: ${userAgent}
                                Forwarded For: ${forwardedFor}
                                Language: ${language}
                            `))

                        return res.status(200).json({
                            message: 'User successfully found.',
                            user: {
                                id: user.id,
                                username: user.username,
                                email: user.email
                            }
                        });
                    } catch (error) {
                        console.error('Error sending message to Discord:', error.message);
                    }
                } else {
                    try {
                        await usersIdGetWebhook.send(new MessageBuilder()
                            .setTitle(`Sent User: ${user.id}`)
                            .setColor('#FA00FF')
                            .setDescription(`
                                Users IP: ${userIp}
                                User Agent: ${userAgent}
                                Forwarded For: ${forwardedFor}
                                Language: ${language}
                            `))

                        return res.status(200).json({
                            message: 'User successfully found.',
                            user: {
                                id: user.id,
                                username: user.username
                            }
                        });
                    } catch (error) {
                        console.error('Error sending message to Discord:', error.message);
                    }
                }
            }
        }
    });
});

router.post('/users/:id', async(req, res) => {
    const { id } = req.params;
    const { body } = req;
    const userIp = req.ipInfo.ip;
    const userAgent = req.headers['user-agent'];
    const forwardedFor = req.headers['x-forwarded-for'];
    const language = req.headers['accept-language'];

    if (!id) {
        return res.json({
            message: "No user's id? Please specify!",
            error: "NO-USER-ID"
        });
    } else if (!body) {
        return res.json({
            message: "No user's info? Please specify!",
            error: "NO-USER-INFO"
        });
    }

    const parsedId = parseInt(id);
    const isInt = utils.isInt(parsedId);

    if (!isInt) {
        return res.json({
            message: "User's id isn't a number! Please specify an integer.",
            error: "USER-ID-NOT-INT"
        });
    }

    if (!body.username && !body.password && !body.email) {
        return res.json({
            message: "No fields provided for update. Please specify at least one field (username, password, email).",
            error: "NO-FIELDS-FOR-UPDATE"
        });
    }

    if (body.password) {
        const hashedPassword = await bcrypt.hash(body.password, 10);
        body.password = hashedPassword;
    }

    const storedPassword = db.get('SELECT password FROM users WHERE id = ?', [parsedId], async (err, user) => {
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
                    `))

                console.error(err.message);
                return res.status(500).json({
                    message: 'Internal Server Error',
                    error: err.message
                });
            } catch (error) {
                console.error('Error sending message to Discord:', error.message);
            }
        }
        return user.password;
    });

    if (body.password !== storedPassword) {
        return res.status(400).json({
            message: "Password doesn't match the stored password.",
            error: "PASSWORD-MISMATCH"
        });
    }

    const updateFields = [];
    const values = [];


    if (body.username) {
        updateFields.push('username = ?');
        values.push(body.username);
    }
    if (body.password) {
        updateFields.push('password = ?');
        values.push(body.password);
    }
    if (body.email) {
        updateFields.push('email = ?');
        values.push(body.email);
    }

    db.run(`UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`, [...values, parsedId], async function (err) {
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
                    `))

                console.error(`Error executing SQL: ${this.error}`);
                console.error(`Error executing SQL: ${err.message}`);
                return res.status(500).json({
                    message: 'Internal Server Error',
                    error: err.message
                });
            } catch (error) {
                console.error('Error sending message to Discord:', error.message);
            }
        }
        try {
            await usersIdPostWebhook.send(new MessageBuilder()
                .setTitle(`User Updated: ${err.message}`)
                .setColor('#FA00FF')
                .setDescription(`
                    Users IP: ${userIp}
                    User Agent: ${userAgent}
                    Forwarded For: ${forwardedFor}
                    Language: ${language}
                `))

            console.log(`User with ID ${parsedId} has been updated.`);
            return res.status(200).json({
                message: 'User successfully updated.',
                updatedUser: {
                    id: parsedId,
                    username: body.username
                }
            });
        } catch (error) {
            console.error('Error sending message to Discord:', error.message);
        }
    });
});

module.exports = router;