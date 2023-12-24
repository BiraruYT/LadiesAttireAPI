// Requires
const express = require('express');
const SQLITE3 = require("better-sqlite3");
const multer = require("multer");
const NodeClam = require('clamscan');
const { JSDOM } = require('jsdom');
const argon2 = require("argon2");
const crypto = require('crypto');

// DOMPurify
const createDOMPurify = require('dompurify');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// Multer
// noinspection JSUnusedGlobalSymbols
const storage = multer.diskStorage({
    destination: function(req, file, cb) {
        cb(null, './uploads/images/users/');
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

// ClamScan
const clamscan = new NodeClam().init({
    removeInfected: true, // Removes files if they are infected
    quarantineInfected: './node-clam/infected/', // Move files here if they are infected
    scanLog: './node-clam/log/', // You're a detail-oriented virus logger
    debugMode: true, // Whether to log info/debug statements
    clamscan: {
        path: 'S:/ClamAV/clamscan.exe', // <-- change this to the correct path
        db: 'S:/ClamAV/database',
        scanArchives: true,
        active: true
    },
    clamdscan: {
        path: 'S:/ClamAV/clamd.exe', // <-- provide the correct path here
        config_file: 'S:/ClamAV/clamd.conf',
        multiscan: true,
        reloadDb: true,
        active: true,
        bypass_test: false,
    },
    preference: "clamdscan"
});

// Local JS Files
const utils = require("../js/utils");
const fs = require("fs");
const imageSize = require("image-size");
const path = require("path");

// Router
const router = express.Router();

// Database
const dbPath = './sqlitedb/dev-users.db'
let db;
try {
    db = new SQLITE3(dbPath);
} catch (err) {
    console.error('Failed to create database connection', err);
    process.exit(1);
}
db.pragma('journal_mode = WAL');
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firstname TEXT,
    lastname TEXT,
    username TEXT,
    password TEXT,
    email TEXT,
    icon TEXT,
    iconext TEXT
  )
`).run();

function deleteFile(file, res = null) {
    if (!file) {
        console.log('No file specified');
        return;
    }
    if (!res || !file.path || !file.destination || file.destination !== './uploads/images/users/') {
        console.log('Invalid file or file path');
        return;
    }

    fs.unlink(file.path, (err) => {
        if (err) {
            console.error('Error deleting file:', err);
            if (res) {
                handleError(err, res);
            }
        }
    });

    return true;
}

function handleError(err, res) {
    if (!res) {
        console.log(err);
        return;
    }
    console.log(err);
    return res.status(500).json({message: 'Internal Server Error'});
}

router.get('/users/:id', async (req, res) => {
    const id = req.params.id;
    let body;

    try {
        body = req.body;
    }
    catch (err) {
        return handleError(err, res);
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

    const stmt = db.prepare('SELECT id, firstname, lastname, username, password, email, icon, iconext FROM users WHERE id = ?');
    const user = stmt.get(parsedId);

    if (!user) {
        return res.status(404).json({
            message: "User not found!",
            error: "USER-NOT-FOUND",
            csrfToken: req.csrfToken()
        });
    }

    let hashedPassword

    try {
        hashedPassword = await argon2.hash(DOMPurify.sanitize(body.password));
    }
    catch (err) {
        handleError(err, res);
    }

    if (hashedPassword === user.password) {
        const formattedUser = user.map(user => {
            // noinspection JSUnresolvedReference
            return [`${user.id}: ${user.firstname},`, `${user.lastname},`, `${user.username},`, `${user.password},`, `${user.email}`, `${user.icon}`, `${user.iconext}`];
        });

        return res.status(200).json({
            user: formattedUser,
            csrfToken: req.csrfToken()
        });
    } else {
        const formattedUser = user.map(user => {
            // noinspection JSUnresolvedReference
            return [`${user.id}: ${user.username},`, `${user.icon}`, `${user.iconext}`];
        });
        return res.status(200).json({
            user: formattedUser,
            csrfToken: req.csrfToken()
        });
    }
});

router.post('/users/register', uploadicon.single('icon'), async (req, res) => {
    let body;

    try {
        body = req.body;
    }
    catch (err) {
        return handleError(err, res);
    }

    const firstname = DOMPurify.sanitize(body.firstname);
    const lastname = DOMPurify.sanitize(body.lastname);
    const username = DOMPurify.sanitize(body.username);
    const password = DOMPurify.sanitize(body.password);
    const email = DOMPurify.sanitize(body.email);

    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    const alphabetRegex = /^[a-zA-Z0-9]+$/;
    const usernameRegex = /^[a-zA-Z0-9_]{3,16}$/;
    const spaceRegex = /\s/;

    if (!firstname && !lastname && !username && !password && !email && !req.file) {
        return res.status(400).json({
            message: 'Missing information!',
            error: 'MISSING-INFORMATION',
            csrfToken: req.csrfToken()
        });
    }

    const icon = req.file;

    clamscan.then(clamscan => {
        try {
            const {isInfected, file, viruses} = clamscan.isInfected(icon.path);
            if (isInfected) {
                console.log(`${file} is infected with ${viruses}!`);
                return res.status(400).json({
                    message: `Uploaded file is infected. Viruses: ${viruses}`,
                    error: 'INFECTED-FILE',
                    csrfToken: req.csrfToken()
                });
            }
        } catch (err) {
            console.log(err);
            deleteFile(icon);
            return handleError(err, res);
        }
    }).catch(err => {
        console.log(err);
        deleteFile(icon);
        return handleError(err, res);
    });

    if (typeof firstname !== 'string' && typeof lastname !== 'string' && typeof username !== 'string' && typeof password !== 'string' && typeof email !== 'string') {
        deleteFile(icon);
        return res.status(400).json({
            message: 'Invalid information!',
            error: 'INVALID-INFORMATION',
            csrfToken: req.csrfToken()
        });
    }

    if (!spaceRegex.test(firstname) && !spaceRegex.test(lastname) && !spaceRegex.test(username) && !spaceRegex.test(password) && !spaceRegex.test(email)) {
        deleteFile(icon);
        return res.status(400).json({
            message: 'Invalid information!',
            error: 'INVALID-INFORMATION',
            csrfToken: req.csrfToken()
        });
    }
    if (!alphabetRegex.test(firstname) && !alphabetRegex.test(lastname) && !usernameRegex.test(username) && !emailRegex.test(email)) {
        deleteFile(icon);
        return res.status(400).json({
            message: 'Invalid information!',
            error: 'INVALID-INFORMATION',
            csrfToken: req.csrfToken()
        });
    }

    if (firstname.length > 15) {
        deleteFile(icon);
        return res.status(400).json({
            message: 'Username exceeds the maximum length of 15 characters.',
            error: "USERNAME-TOO-LONG",
            csrfToken: req.csrfToken()
        });
    }
    else if (lastname.length > 15) {
        deleteFile(icon);
        return res.status(400).json({
            message: 'Username exceeds the maximum length of 15 characters.',
            error: "USERNAME-TOO-LONG",
            csrfToken: req.csrfToken()
        });
    }
    else if (username.length > 15) {
        deleteFile(icon);
        return res.status(400).json({
            message: 'Username exceeds the maximum length of 15 characters.',
            error: "USERNAME-TOO-LONG",
            csrfToken: req.csrfToken()
        });
    }
    else if (password.length > 30) {
        deleteFile(icon);
        return res.status(400).json({
            message: 'Password exceeds the maximum length of 30 characters.',
            error: "PASSWORD-TOO-LONG",
            csrfToken: req.csrfToken()
        });
    }
    else if (email.length > 40) {
        deleteFile(icon);
        return res.status(400).json({
            message: 'Email exceeds the maximum length of 40 characters.',
            error: "EMAIL-TOO-LONG",
            csrfToken: req.csrfToken()
        });
    }

    const dimensions = imageSize(icon.path);

    if (!dimensions.width || !dimensions.height) {
        deleteFile(icon);
        return res.status(400).json({
            message: 'Uploaded file is not an image.',
            error: 'NOT_AN_IMAGE',
        });
    }

    const iconBase64 = fs.readFileSync(icon.path).toString('base64');
    const ext = path.extname(icon.originalname);

    let argon2HashedPassword
    const salt = crypto.randomBytes(32);

    try {
        argon2HashedPassword = DOMPurify.sanitize(await argon2.hash(password, { salt }));
    }
    catch (err) {
        deleteFile(icon);
        return handleError(err, res);
    }

    const newUser = {
        firstname: firstname,
        lastname: lastname,
        username: username,
        password: argon2HashedPassword,
        email: email,
        icon: iconBase64,
        iconext: ext,
    };

    const stmtexist = db.prepare('SELECT id FROM users WHERE firstname = ? OR lastname = ? OR username = ? OR email = ?');
    const existingUser = stmtexist.get(newUser.firstname, newUser.lastname, newUser.username, newUser.email);

    if (existingUser) {
        deleteFile(icon);
        return res.status(400).json({
            message: 'User with the same first or last or username or email already exists.',
            error: 'USER-ALREADY-EXISTS',
            existingUserId: existingUser.id,
            csrfToken: req.csrfToken()
        });
    }

    const stmtinsert = db.prepare('INSERT INTO users (firstname, lastname, username, password, email, icon, iconext) VALUES (?, ?, ?, ?, ?, ?, ?)');
    const result = stmtinsert.run(newUser.firstname, newUser.lastname, newUser.username, newUser.password, newUser.email, newUser.icon, newUser.iconext);

    if (!result) {
        deleteFile(icon);
        return handleError("Failed to insert user into database.", res);
    }

    console.log(`A new user has been added with ID ${result.id}`);
    return res.status(200).json({
        message: 'User successfully added.',
        newUser: {
            id: result.id,
            firstname: newUser.firstname,
            lastname: newUser.lastname,
            username: newUser.username,
            email: newUser.email,
            icon: newUser.icon,
            iconext: newUser.iconext,
        },
        csrfToken: req.csrfToken()
    });
});

router.patch('/users/:id', async (req, res) => {
    const id = req.params.id;
    let body;

    try {
        body = req.body;
    }
    catch (err) {
        return handleError(err, res);
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

    const firstname = DOMPurify.sanitize(body.firstname);
    const lastname = DOMPurify.sanitize(body.lastname);
    const username = DOMPurify.sanitize(body.username);
    // noinspection JSUnresolvedReference
    const originalpassword = DOMPurify.sanitize(body.originalpassword);
    // noinspection JSUnresolvedReference
    const newpassword = DOMPurify.sanitize(body.newpassword);
    const email = DOMPurify.sanitize(body.email);
    const icon = req.file;

    if (firstname || lastname || username || newpassword || email || icon) {
        if (!originalpassword) {
            return res.status(400).json({
                message: 'Missing information!',
                error: 'MISSING-INFORMATION',
                csrfToken: req.csrfToken()
            });
        }

        const stmt = db.prepare('SELECT password FROM users WHERE id = ?')
        const user = stmt.get(parsedId);

        if (!user) {
            return res.status(400).json({
                message: `User with ID ${parsedId} not found.`,
                error: "USER-NOT-FOUND",
                csrfToken: req.csrfToken()
            });
        }

        if (!await argon2.verify(user.password, originalpassword)) {
            return res.status(400).json({
                message: 'Invalid information!',
                error: 'INVALID-INFORMATION',
                csrfToken: req.csrfToken()
            });
        }

        if (originalpassword === newpassword) {
            return res.status(400).json({
                message: 'New password cannot be the same as the old password!',
                error: 'SAME-PASSWORD',
                csrfToken: req.csrfToken()
            });
        }

        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        const alphabetRegex = /^[a-zA-Z0-9]+$/;
        const usernameRegex = /^[a-zA-Z0-9_]{3,16}$/;
        const spaceRegex = /\s/;

        if (typeof firstname !== 'string' && typeof lastname !== 'string' && typeof username !== 'string' && typeof newpassword !== 'string' && typeof email !== 'string') {
            deleteFile(icon);
            return res.status(400).json({
                message: 'Invalid information!',
                error: 'INVALID-INFORMATION',
                csrfToken: req.csrfToken()
            });
        }

        if (!spaceRegex.test(firstname) && !spaceRegex.test(lastname) && !spaceRegex.test(username) && !spaceRegex.test(newpassword) && !spaceRegex.test(email)) {
            deleteFile(icon);
            return res.status(400).json({
                message: 'Invalid information!',
                error: 'INVALID-INFORMATION',
                csrfToken: req.csrfToken()
            });
        }
        if (!alphabetRegex.test(firstname) && !alphabetRegex.test(lastname) && !usernameRegex.test(username) && !emailRegex.test(email)) {
            deleteFile(icon);
            return res.status(400).json({
                message: 'Invalid information!',
                error: 'INVALID-INFORMATION',
                csrfToken: req.csrfToken()
            });
        }

        if (firstname.length > 15) {
            deleteFile(icon);
            return res.status(400).json({
                message: 'Username exceeds the maximum length of 15 characters.',
                error: "USERNAME-TOO-LONG",
                csrfToken: req.csrfToken()
            });
        }
        else if (lastname.length > 15) {
            deleteFile(icon);
            return res.status(400).json({
                message: 'Username exceeds the maximum length of 15 characters.',
                error: "USERNAME-TOO-LONG",
                csrfToken: req.csrfToken()
            });
        }
        else if (username.length > 15) {
            deleteFile(icon);
            return res.status(400).json({
                message: 'Username exceeds the maximum length of 15 characters.',
                error: "USERNAME-TOO-LONG",
                csrfToken: req.csrfToken()
            });
        }
        else if (newpassword.length > 30) {
            deleteFile(icon);
            return res.status(400).json({
                message: 'Password exceeds the maximum length of 30 characters.',
                error: "PASSWORD-TOO-LONG",
                csrfToken: req.csrfToken()
            });
        }
        else if (email.length > 40) {
            deleteFile(icon);
            return res.status(400).json({
                message: 'Email exceeds the maximum length of 40 characters.',
                error: "EMAIL-TOO-LONG",
                csrfToken: req.csrfToken()
            });
        }

        if (icon) {
            clamscan.then(clamscan => {
                try {
                    const {isInfected, file, viruses} = clamscan.isInfected(icon.path);
                    if (isInfected) {
                        console.log(`${file} is infected with ${viruses}!`);
                        return res.status(400).json({
                            message: `Uploaded file is infected. Viruses: ${viruses}`,
                            error: 'INFECTED-FILE',
                            csrfToken: req.csrfToken()
                        });
                    }
                } catch (err) {
                    console.log(err);
                    deleteFile(icon);
                    return handleError(err, res);
                }
            }).catch(err => {
                console.log(err);
                deleteFile(icon);
                return handleError(err, res);
            });

            const dimensions = imageSize(icon.path);

            if (!dimensions.width || !dimensions.height) {
                deleteFile(icon);
                return res.status(400).json({
                    message: 'Uploaded file is not an image.',
                    error: 'NOT_AN_IMAGE',
                });
            }

            const iconBase64 = fs.readFileSync(icon.path).toString('base64');
            const ext = path.extname(icon.originalname);

            const updateFields = [];
            const values = [];

            if (firstname) {
                updateFields.push('firstname = ?');
                values.push(firstname);
            }
            if (lastname) {
                updateFields.push('lastname = ?');
                values.push(lastname);
            }
            if (username) {
                updateFields.push('username = ?');
                values.push(username);
            }
            if (newpassword) {
                updateFields.push('password = ?');
                values.push(newpassword);
            }
            if (email) {
                updateFields.push('email = ?');
                values.push(email);
            }
            if (icon) {
                updateFields.push('icon = ?');
                updateFields.push('iconext = ?');
                values.push(iconBase64);
                values.push(ext);
            }

            const stmt = db.prepare(`UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`)
            const result = stmt.run([...values, parsedId]);

            // noinspection JSUnresolvedReference
            if (result.changes > 0) {
                const stmtupdate = db.prepare('SELECT id, firstname, lastname, username, email, icon, iconext FROM users WHERE id = ?')
                const updatedUser = stmtupdate.get(parsedId);

                console.log(`User with ID ${parsedId} has been updated.`);
                return res.status(200).json({
                    message: 'User successfully updated.',
                    updatedUser: updatedUser,
                    csrfToken: req.csrfToken()
                });
            }
            else {
                handleError("Database Error", res)
            }
        }
    }
    else {
        return res.status(400).json({
            message: 'Missing information!',
            error: 'MISSING-INFORMATION',
            csrfToken: req.csrfToken()
        });
    }
});

router.delete('/users/:id', async (req, res) => {

});

module.exports = router;