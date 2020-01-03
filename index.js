const express = require("express");
const app = express();
const models = require('./models');
const bodyParser = require("body-parser");

var pbkdf2 = require('pbkdf2');
var salt = "4213426A433E1F9C29368F36F44F1";

function encryptionPassword(password) {
  var key = pbkdf2.pbkdf2Sync(
    password, salt, 36000, 256, 'sha256'
  );
  var hash = key.toString('hex');

  return hash;
}

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.use(express.static(__dirname + '/public'));

/*  PASSPORT SETUP  */

const passport = require('passport');
app.use(passport.initialize());
app.use(passport.session());

app.get('/success', (req, res) => res.send("Welcome " + req.query.username + "!!"));
app.get('/error', (req, res) => res.send("error logging in"));

passport.serializeUser(function (user, cb) {
  cb(null, user.id);
});

passport.deserializeUser(function (id, cb) {
  models.user.findOne({ where: { id: id } }).then(function (user) {
    cb(null, user);
  });
});

/* PASSPORT LOCAL AUTHENTICATION */

const LocalStrategy = require('passport-local').Strategy;

passport.use(new LocalStrategy(
  function (username, password, done) {
    models.user.findOne({
      where: {
        username: username
      }
    }).then(function (user) {
      if (!user) {
        return done(null, false);
      }

      if (user.password != encryptionPassword(password)) {
        return done(null, false);
      }
      return done(null, user);
    }).catch(function (err) {
      return done(err);
    });
  }
));

app.post('/',
  passport.authenticate('local', { failureRedirect: '/error' }),
  function(req, res) {
    res.redirect('/success?username='+req.user.username);
  });



app.post("/sign-up", function (req, response) {
  models.user.create({ 
    username: req.body.username, 
    password: encryptionPassword(req.body.password)
  })
    .then(function (user) {
      response.send(user);
    });
});

app.listen(3000, function () {
  console.log('server listening on port 3000');
})