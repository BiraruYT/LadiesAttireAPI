const express = require('express');
const expressip = require('express-ip');
const helmet = require('helmet');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const keys = require("./js/keys");

const app = express();
const PORT = process.env.PORT || 8080;

const index = require('./routes/index.js');
const users = require('./routes/users.js');
const services = require('./routes/services.js');
const usertoid = require('./routes/services/user-to-id.js');

// CSRF Protection Setup
const csrfProtection = csrf({ cookie: true });

app.use(helmet());
app.use(cors());
app.use(cookieParser(keys.keys.cookieparser));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(expressip().getIpInfoMiddleware);
app.use(csrfProtection);

app.use(
    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'"],
            imgSrc: ["'self'"],
        },
    })
);

app.get('/', index);
app.get('/users', users);
app.get('/services', services);
app.get('/services/user-to-id', usertoid);
app.get('/users/:id', rateLimit, users);
app.get('/services/user-to-id:id', rateLimit, usertoid);

app.post('/users', csrfProtection, rateLimit, users);
app.post('/users/:id', csrfProtection, rateLimit, users);

app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
    console.log(`Server is hosted at http://localhost:${PORT}`)
});