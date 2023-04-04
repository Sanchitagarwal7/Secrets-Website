//jshint esversion:6
require('dotenv').config()
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption');
const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
const passport = require('passport');
const session = require('express-session');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
///////////////////////////////////////////////////START SESSION/////////////////////////////////////////////////////////


app.use(session({
  secret: 'I am Iron-Man',
  resave: false,
  saveUninitialized: true,
}));

////////////////////////////////////////////INITIALIZE PASSPORT////////////////////////////////////////////////////////////////

app.use(passport.initialize());   //initialize passport package
app.use(passport.session());     //start the session you have built above

/////////////////////////////////////////////////CONNECT TO MONGODB///////////////////////////////////////////////////////////

mongoose.connect('mongodb+srv://sanchitag893:Sanchit1@cluster2.ivxiviw.mongodb.net/userDB', {useNewUrlParser: true});

//////////////////////////////////////////////////ARRAY TO STORE INDIVIDUAL SECRETS//////////////////////////////////////////////////////////

const multiple = [];

////////////////////////////////////////////////////////////MAKE SCHEMA////////////////////////////////////////////////

const Schema = mongoose.Schema;

const userSchema = new Schema({
    username: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: multiple
});

/////////////////////////////////////ESTABLISH PLUGINS///////////////////////////////////////////////////////////////////////

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// const secret_key = process.env.SECRET_KEY;
// userSchema.plugin(encrypt, {secret: secret_key, encryptedFields: ['password']});

const User = new mongoose.model('User', userSchema);


// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function(user, done) {
  done(null, user);
});
 
passport.deserializeUser(function(user, done) {
  done(null, user);
});

//////////////////////////////////////////GOOGLE STRATEGY LOGIN//////////////////////////////////////////////////////////////////

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  // console.log(profile);
  User.findOrCreate({ googleId: profile.id, username: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

//////////////////////////////////////////FACEBOOK STRATEGY LOGIN//////////////////////////////////////////////////////////////////

passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  User.findOrCreate({ facebookId: profile.id, username: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

app.get('/',(req, res)=>{
    res.render('home');
});

//////////////////////////////////////////GOOGLE AUTHENTICATION//////////////////////////////////////////////////////////////////

app.get('/auth/google',
  passport.authenticate('google', {scope: ['profile']})
);

app.get( '/auth/google/secrets',
    passport.authenticate( 'google', {
        successRedirect: '/secrets',
        failureRedirect: '/login'
}));

//////////////////////////////////////////FACEBOOK AUTHENTICATION//////////////////////////////////////////////////////////////////

app.get('/auth/facebook',
  passport.authenticate('facebook')
);

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });



app.get('/login',(req, res)=>{
    res.render('login');
});

app.get('/register',(req, res)=>{
    res.render('register');
});

app.get('/secrets',(req, res)=>{
  User.find({secret: {$ne: null}})
    .then((foundUsers)=>{
      res.render('secrets', {usersSecrets: foundUsers});
    })
    .catch((err)=>{
      console.log(err);
    })
  ;
});

app.get('/secrets', (req, res)=>{
  if(req.isAuthenticated()){
    res.render('secrets');
  }else{
    res.redirect('/login');
  }
});

app.get('/submit', (req, res)=>{
  if(req.isAuthenticated()){
    res.render('submit');
  }else{
    res.redirect('/login');
  }
});

app.post('/submit', (req, res)=>{
  const submittedSecret = req.body.secret;

  User.findById({_id: req.user._id})
    .then((foundUser)=>{
      if(foundUser){
        foundUser.secret.push(submittedSecret);
        foundUser.save();
      }
      res.redirect('/secrets');
    })
    .catch((err)=>{
      console.log(err);
    })
  ;
});

app.post('/register', (req, res)=>{
  
    // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    //   // Store hash in your password DB.
    //   const newUser = new User({
    //     email: req.body.username,
    //     password: hash              //md5(req.body.password)  //hashed
    // });
    // newUser.save()
    //   .then(()=>{
    //     // console.log('Added new User');
    //     res.render('secrets');
    //   })
    //   .catch((err)=>{
    //     console.log(err);
    //   })
    // ;
    // });

    User.register({username: req.body.username}, req.body.password, function(err, user){
      if(err){
        console.log(err);
        res.redirect('/login');
      }else{
        passport.authenticate('local')(req, res, function(){
          res.redirect('/secrets');
        });
      }
    });

});

// app.post('/login',(req, res)=>{
//     // const username = req.body.username;
//     // const password = req.body.password;   //md5(req.body.password);  //hashed

//     // User.findOne({email: username})
//     //   .then((foundUser)=>{
//     //     bcrypt.compare(password, foundUser.password /*hash*/, function(err, result) { //Load 'hash' from your database and 'password' is the user typed password
//     //       // result == true
//     //       if(result === true){
//     //         res.render('secrets');
//     //       }
//     //     });
//     //   })
//     //   .catch((err)=>{
//     //     console.log(err);
//     //   })
//     // ;
// });

app.post('/login', 
  passport.authenticate('local', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });

app.get('/logout', (req, res)=>{
  req.logout(function(err){
    if(err){
      console.log(err);
    }else{
      res.redirect('/');
    }
  });
});

app.listen(3000, ()=>{
    console.log('Server is running on port 3000');
})