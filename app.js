const express = require('express');
const expressip = require('express-ip');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 8080;

const index = require('./routes/index.js');
const users = require('./routes/users.js');
const services = require('./routes/services.js');
const usertoid = require('./routes/services/user-to-id.js');

const options = {
    hostname: 'www.google.com',
    port: 80,
    path: '/',
    method: 'GET',
};
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per windowMs minutes
    message: 'Too many requests from this IP, please try again later.',
});
const req = https.request(options, (res) => {
    if (res.statusCode === 200) {
        console.log('Connected to the internet.');
    }
    console.log(`Status Code While Connecting: ${res.statusCode}`);
});
req.on('error', (error) => {
    console.error(`Error connecting to the internet: ${error.message}`);
});


app.use(helmet());
app.use(limiter);
app.use(express.json());
app.use(expressip().getIpInfoMiddleware);

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
app.get('/users/:id', users);
app.get('/services/user-to-id:id', usertoid);


app.post('/users', users);
app.post('/users/:id', users);

app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
    console.log(`Server is hosted at http://localhost:${PORT}`)
});

req.end();