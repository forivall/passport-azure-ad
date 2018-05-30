
const express = require('express')
const he = require('he')
const passport = require('passport')
const bodyParser = require('body-parser')
const expressSession = require('express-session')
const cookieParser = require('cookie-parser')
const {OIDCStrategy} = require('..')

const log = require('bunyan').createLogger({
  name: 'Example Azure AD App',
  level: 'info',
  stream: process.stdout
})

var users = [];

var findByOid = function(oid, fn) {
  for (var i = 0, len = users.length; i < len; i++) {
    var user = users[i];
    if (user.profile.oid === oid) {
      return fn(null, user);
    }
  }
  return fn(null, null);
};

passport.serializeUser(function(user, done) {
  done(null, user.oid);
});

passport.deserializeUser(function(oid, done) {
  findByOid(oid, function (err, user) {
    done(err, user);
  });
});
passport.use(new OIDCStrategy(Object.assign({
  // responseType: 'id_token',
  responseType: 'code id_token',
  responseMode: 'form_post',
  redirectUrl: 'http://localhost:8080/auth/msal/return',
  allowHttpForRedirectUrl: true,
  validateIssuer: true,
  issuer: null,
  useCookieInsteadOfSession: true,
  scope: ['profile'], // , '53556ed4-60bc-4f25-9e09-c220543ef656/login'
  loggingLevel: 'info',
  loggingNoPII: true,
  passReqToCallback: true
}, require('./config')), function(req, iss, sub, profile, jwtClaims, accessToken, refreshToken, params, done) {
  if (!profile.oid) {
    return done(new Error("No oid found"), null);
  }
  findByOid(profile.oid, function(err, user) {
    if (err) {
      return done(err);
    }
    if (!user) {
      // "Auto-registration"
      users.push({iss, sub, profile, jwtClaims, accessToken, refreshToken, idToken: params.id_token, code: req.body.code});
      return done(null, profile);
    }
    return done(null, user);
  });
}))

const page = `<!DOCTYPE html>
<style>
html { display: flex; flex-direction: column; }
body {
  display: flex;
  align-items: center;
  align-content: center;
  justify-content: center;
  flex-direction: column;
}
dl {
  max-width: 100%;
}
tt {
  word-wrap: break-word;
}
input {
  font-size: xx-large;
  font-weight: bold;
}
</style>
<form method="post" action="/auth/msal/login"><input type="submit" value="Login"></form>
`

const app = express()
app.use(cookieParser())
app.use(bodyParser.urlencoded({extended: true}))
app.use(expressSession({secret: 'bearded dragon', resave: true, saveUninitialized: false}))
app.use(passport.initialize())
app.use(passport.session())
app.get('/', (req, res) => {
  let html = page

  if (req.user) {
    const user = req.user
    html += `<p>Hello <em>${he.encode(user.profile.displayName)}</em></p>`
    html += `<dl>`
    html += `<dt>iss:</dt><dd>${user.iss}</dd>`
    html += `<dt>sub:</dt><dd>${user.sub}</dd>`
    const profile = Object.assign({}, user.profile, {_raw: undefined})
    html += `<dt>profile:</dt><dd><pre>${JSON.stringify(profile, null, '  ')}</pre></dd>`
    html += `<dt>accessToken:</dt><dd><tt>${user.accessToken}</tt></dd>`
    html += `<dt>refreshToken:</dt><dd><tt>${user.refreshToken}</tt></dd>`
    html += `<dt>idToken:</dt><dd><tt>${user.idToken}</tt></dd>`
    html += `<dt>code:</dt><dd><tt>${user.code}</tt></dd>`
    html += `</dl>`
    // iss, sub, profile, accessToken, refreshToken
  } else {
    html += `<p>You are not logged in</p>`
  }

  res.status(200).type('html').send(html)
})
const doAuth = [
  passport.authenticate('azuread-openidconnect', {failureRedirect: '/'}),
  (req, res) => {
    log.info('logged in!')
    res.redirect('/')
  }
]
app.post('/auth/msal/login', doAuth)
app.get('/auth/msal/return', doAuth)
app.post('/auth/msal/return', doAuth)

app.listen(8080)