const express = require('express');
const { rateLimit } = require('express-rate-limit');
const helmet = require('helmet');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const keys = require("./js/keys");

const app = express();
const PORT = process.env.PORT || 8080;

const users = require('./routes/users.js');
const usertoid = require('./routes/services/user-to-id.js');

const csrfProtection = csrf({ cookie: true });
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
const scriptContent = `if ('serviceWorker' in navigator) {
          navigator.serviceWorker.register('/service-worker.js')
              .then(registration => console.log('Service Worker registered with scope:', registration.scope))
              .catch(error => console.error('Service Worker registration failed:', error));
      }`;
const hash = crypto.createHash('sha256').update(scriptContent).digest('base64');

// noinspection JSCheckFunctionSignatures
app.use(limiter);
app.use(helmet());
app.use(cors());
app.use(cookieParser(keys.keys.cookieparser));
app.use(express.static('public'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(csrfProtection);

app.use(
    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", `'sha256-${hash}'`],
            styleSrc: ["'self'"],
            imgSrc: ["'self'"],
        },
    })
);
app.use((req, res, next) => {
    // noinspection JSUnresolvedReference
    res.locals.csrfToken = req.csrfToken();
    next();
});
// noinspection JSCheckFunctionSignatures
app.use((err, req, res, next) => {
    // noinspection JSUnresolvedReference
    if (err.code === 'EBADCSRFTOKEN') {
        // noinspection JSUnresolvedReference
        res.status(403).json({
            error: 'CSRF token validation failure'
        });
    } else {
        next(err);
    }
});
app.use((req, res, next) => {
    const userAgent = req.headers['user-agent'];
    const isAndroid = userAgent.toLowerCase().includes('android');
    const isPC = !isAndroid;

    req.isAndroid = isAndroid;
    req.isPC = isPC;

    next();
});

app.get('/users/:id', users);
app.get('/services/user-to-id/:username', usertoid);

app.post('/users', users);
app.post('/users/:id', users);

app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
    console.log(`Server is hosted at http://localhost:${PORT}`)
});