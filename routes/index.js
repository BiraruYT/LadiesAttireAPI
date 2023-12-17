var express = require('express');

var router = express.Router();

router.get('/', function(req, res) {
    return res.status(400).json({
        message: "Nothing exists here so get out before everything collapses!",
        error: "NOTHING-EXISTS-HERE",
    });
});

module.exports = router;