/*router.post('/users/:id', async (req, res) => {
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

    try {
        if (!body.update.username && !body.update.password && !body.update.email) {
            return res.status(400).json({
                message: `No fields provided for update. Please specify at least one field update{username, password, email}.`,
                error: "NO-FIELDS-FOR-UPDATE",
                csrfToken: req.csrfToken()
            });
        }
    }
    catch (err) {
        return res.status(400).json({
            message: `No fields provided for update. Please specify at least one field update{username, password, email}.`,
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

        let isPasswordMatch
        try {
            isPasswordMatch = await argon2.verify(user.password, body.password);
        }
        catch (err) {
            return res.status(500).json({
                message: 'Internal Server Error',
                csrfToken: req.csrfToken()
            });
        }

        if (!isPasswordMatch) {
            return res.status(400).json({
                message: "Password doesn't match the stored password.",
                error: "PASSWORD-MISMATCH",
                csrfToken: req.csrfToken()
            });
        }

        const updateFields = [];
        const values = [];

        if (body.update.username) {
            updateFields.push('username = ?');
            values.push(DOMPurify.sanitize(body.update.username));
        }
        if (body.update.password) {
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
            updateFields.push('email = ?');
            values.push(DOMPurify.sanitize(body.update.email));
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

                const updatedUser = db.prepare('SELECT id, username, email FROM users WHERE id = ?').get(parsedId);

                console.log(`User with ID ${parsedId} has been updated.`);
                return res.status(200).json({
                    message: 'User successfully updated.',
                    updatedUser: updatedUser,
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
});*/