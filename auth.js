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
            callbackURL: /auth/google/callback
        },
        (token, refreshToken, profile, done) => {
            return done(null, {
                profile: profile,
                token: token
            });
        }));
};