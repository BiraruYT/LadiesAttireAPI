const express = require('express');
const { rateLimit } = require('express-rate-limit');
const helmet = require('helmet');
const session = require('express-session');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');
const keys = require("./js/keys");

const app = express();
const PORT = process.env.PORT || 8080;

const users = require('./old/users-old.js');
const newarrivals = require('./routes/newarrivals.js');
const usertoid = require('./routes/user-to-id.js');

const csrfProtection = csrf({ cookie: true });
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
const scriptContent = `if ('serviceWorker' in navigator) {
          navigator.serviceWorker.register('./public/service-worker.js')
              .then(registration => console.log('Service Worker registered with scope:', registration.scope))
              .catch(error => console.error('Service Worker registration failed:', error));
      }`;
const hash = crypto.createHash('sha256').update(scriptContent).digest('base64');

export const usersDB = './sqlitedb/dev-users.db';
export const productsDB = './sqlitedb/dev-products.db';

// noinspection JSCheckFunctionSignatures
app.use(limiter);
app.use(helmet());
app.use(session({
    secret: keys.keys.session,
    resave: false,
    saveUninitialized: true
}));
app.use(cors());
app.use(cookieParser(keys.keys.cookieparser));
app.use(express.static('public'));
app.use(bodyParser.json({ limit: '1mb'}));
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

app.get('/newarrivals', newarrivals);
app.get('/user-to-id/:username', usertoid);
app.get('/users/:id/info', users);

app.post('/newarrivals', newarrivals);
app.post('/users/register', users);
app.post('/users/:id/edit', users);

app.delete('/newarrivals', newarrivals);

app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
    console.log(`Server is hosted at http://localhost:${PORT}`)
});