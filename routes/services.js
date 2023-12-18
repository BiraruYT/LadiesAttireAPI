const express = require('express');

const router = express.Router();

router.get('/services', function(req, res) {
    return res.status(400).json({
        message: "Nothing exists here so get out before everything collapses! But if your looking for some services, you can find them here:",
        services: [
            "services/user-to-id:username"
        ],
        error: "NOTHING-EXISTS-HERE",
        csrfToken: req.csrfToken()
    });
});

module.exports = router;