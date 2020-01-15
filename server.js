const express = require('express'),
const router = express(),
const passport = require('passport'),
const auth = require('./routes/auth'),
const cookieParser = require('cookie-parser'),
const cookieSession = require('cookie-session');

auth(passport);
router.use(passport.initialize());

router.use(cookieSession({
    name: 'session',
    keys: ['123'],
    maxAge: 24 * 60 * 60 * 1000
}));
router.use(cookieParser());

router.get('/', (req, res) => {
    if (req.session.token) {
        res.cookie('token', req.session.token);
        res.json({
            status: 'session cookie set'
        });
    } else {
        res.cookie('token', '')
        res.json({
            status: 'session cookie not set'
        });
    }
});

router.get('/logout', (req, res) => {
    req.logout();
    req.session = null;
    res.redirect('/');
});

router.get('/auth/google', passport.authenticate('google', {
    scope: ['https://www.googleapis.com/auth/userinfo.profile']
}));

router.get('/auth/google/callback',
    passport.authenticate('google', {
        failureRedirect: '/'
    }),
    (req, res) => {
        console.log(req.user.token);
        req.session.token = req.user.token;
        res.redirect('/');
    }
);

router.listen(3000, () => {
    console.log('Server is running on port 3000');
});