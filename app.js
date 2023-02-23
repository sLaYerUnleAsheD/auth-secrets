require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

// this is level 5 security using Passport.js, cookies & sessions.
// to check out previous levels take a look at the previous commits.

const session = require('express-session');
const passport = require('passport');

// we don't need to require passport-local because passport-local-mongoose
// is dependent on it so we installed it for that purpose

const passportLocalMongoose = require('passport-local-mongoose');

const app = express();
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.set('view engine', 'ejs');

//create session with options recommended by documentation
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));


// initialize passport
app.use(passport.initialize());
// use passport to manage our sessions
app.use(passport.session());

mongoose.set('strictQuery', true);
mongoose.connect("mongodb://0.0.0.0:27017/userDB", {useNewUrlParser: true});

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

// plugin passportLocalMongoose into our userSchema, it will perform
// hashing and salting of passwords for us.
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// when we say serializeUser, passport creates the cookie
// puts in the users identification.
passport.serializeUser(function(user, done) {
   done(null, user.id);
});
  
// when we say deserializeUser, passport extracts the info
// from the cookie and authenticates the user.
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});



passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));



app.get('/', function(req, res) {
    res.render("home");
});

// this below get method is present in passport.js google oauth 2.0 strategies doc
// link: https://www.passportjs.org/packages/passport-google-oauth20/

app.get('/auth/google', 
    passport.authenticate('google', { scope: ['profile'] })
);

//after being authenticated the user will be redirected to the 
//privileged page and we deal with that GET request below

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets page.
    res.redirect('/secrets');
  });

app.get('/login', function(req, res) {
    res.render("login");
});

app.get('/register', function(req, res) {
    res.render("register");
});

// when user hits "logout" button we send a get request to logout route
// we simply use the req.logout() of passport.js to deauthenticate the user
// and redirect them to the home page

app.get("/logout", function(req, res) {
    req.logout(function(err) {
        if(err){
            console.log(err);
        }else{
            res.redirect("/");
        }
    });
});

// now for functionality our site actually doesn't need the users to be 
// authenticated to view a secret, so we remove req.isAuthenticated()
app.get("/secrets", function(req, res) {

    // below code looks through all our documents(users in this case), finds secret 
    // fields then check is they have some content ($ne: null means not equal to null)
    // then fetch those users from the database.
    User.find({"secret": {$ne: null}}, function(err, foundUsers) {
        if(err) {
            console.log(err);
        }else{
            if(foundUsers){
                res.render("secrets", {usersWithSecrets: foundUsers})
            }
        }
    });
});

app.get("/submit", function(req, res) {
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res) {
    const submittedSecret = req.body.secret;

    // when a user is logged in our session stores the info about our user
    // such as the username and the id in the "req" so we can tap into the user
    // by req.user
    User.findById(req.user.id, function(err, foundUser) {

        if(err) {
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(function() {
                    res.redirect("/secrets");
                });
            }
        }
    });
});

// both when user has successfully registered or successfully logged in
// we are going to send a cookie to the browser which it will hold on to
// and use it whenever the user tries to access a page that requires authentication
// such as the "Secrets" page

app.post("/register", function(req, res) {

    // passport-local-mongoose acts as a middleman to create a new User document
    // & save it in our database
    // User.register() method takes the username, password, creates user and in 
    // callback function that user is passed as a parameter

    User.register({username: req.body.username}, req.body.password, function(err, user) {
        if(err) {
            console.log(err);
            res.redirect("/register");
        }else{

            // if there were no errors then we locally authenticate user which
            // takes request, response and callback function as parameters
            // this callback is triggered only if the user authentication was
            // successful and their cookie was created with their login info.

            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    })

})

app.post("/login", function(req, res) {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    // req.login() is provided by Passport.js
    // we create a new User document and pass it to login() method
    // then if there was any error in case of wrong username or password
    // we log that error in the callback function or else we locally
    // authenticate the user and redirect them to secrets

    req.login(user, function(err) {
        if(err){
            console.log(err);
        }else{

            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });

});

app.listen(3000, function() {
    console.log("Server started on port 3000");
})
