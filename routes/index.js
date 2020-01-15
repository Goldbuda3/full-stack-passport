const express = require('express');
const router = express.Router();
const auth = require('./auth'),
cookieParser = require('cookie-parser'),
cookieSession = require('cookie-session');

// const app = express();
const session = require("express-session");
const bodyParser = require("body-parser");
require('dotenv').config();
const models = require('../models');

var pbkdf2 = require('pbkdf2');
var salt = process.env.SALT_KEY;

function encryptionPassword(password) {
  var key = pbkdf2.pbkdf2Sync(
    password, salt, 36000, 256, 'sha256'
  );
  var hash = key.toString('hex')
  return hash;
}

router.use(session({
  secret: "cats",
  resave: false,
  saveUninitialized: true
}));
router.use(bodyParser.json());
router.use(bodyParser.urlencoded({ extended: false }));

router.use(express.static(__dirname + '/public'));

/*  PASSPORT SETUP  */

const passport = require('passport');
auth(passport);
router.use(passport.initialize());
router.use(passport.session());

router.get('/success', function (req, res) {
  if (req.isAuthenticated()) {
    res.redirect('/articles')
  } else {
    res.send("not authorized.");
  }
});

router.get('/logout', function (req, res) {
  if (req.isAuthenticated()) {
    console.log("user logging out");
    req.logOut();
    res.send("user has logged out");
  } else {
    res.send("You don't have a session open");
  }
});

router.get('/error', (req, res) => 
(res.redirect('/login')));

passport.serializeUser(function (users, cb) {
  cb(null, users.id);
});

passport.deserializeUser(function (id, cb) {
  models.users.findOne({ where: { id: id } }).then(function (users) {
    cb(null, users);
  });
});

/* PASSPORT LOCAL AUTHENTICATION */

const LocalStrategy = require('passport-local').Strategy;

passport.use(new LocalStrategy(
  function (username, password, done) {
    models.users.findOne({
      where: {
        username: username
      }
    }).then(function (users) {
      if (!users) {
        return done(null, false);
      }
      if (users.password != encryptionPassword(password)) {
        return done(null, false);
      }
      return done(null, users);
    }).catch(function (err) {
      return done(err);
    });
  }
));

router.get('/login', function (req, res) {
  res.render('articles/login');
})

router.post('/login',
  passport.authenticate('local', { failureRedirect: '/error' }),
  function (req, res) {
    // res.render('articles/login');
    res.redirect('/success');
  });

router.post("/sign-up", function (req, response) {
  models.users.create({
    username: req.body.username,
    password: encryptionPassword(req.body.password)
  })
    .then(function (users) {
      response.redirect('/articles');
    });
});

router.get('/sign-up', function (req, res) {
  res.render('articles/sign-up');
})

router.get('/', function (req, res) {
  res.render("articles/login")
});

/* PASSPORT GOOGLE AUTHENTICATION */
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

module.exports = (passport) => {
    passport.serializeUser((user, done) => {
        done(null, user);
    });
    passport.deserializeUser((user, done) => {
        done(null, user);
    });
    passport.use(new GoogleStrategy({
            clientID: 976212040028-hcigl64nfd0vd5u1o1o2qp2arq9qlpde.apps.googleusercontent.com,
            clientSecret: ItHOI71SKWqzgEjSvLGusns8,
            callbackURL: "http://localhost:8080/auth/google/callback"
        },
        (token, refreshToken, profile, done) => {
            return done(null, {
                profile: profile,
                token: token
            });
        }));
};

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

module.exports = router;
