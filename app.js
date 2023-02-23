require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
// commented out because in case of high level breach the .env file is vulnerable
// so we use md5 to hash passwords instead (level 3 security)
// const encrypt= require('mongoose-encryption');

// commented out because brute force attack is still possible
// to crack dictonary passwords so we will use bcrypt instead of md5
// to hash and salt our passwords (level 4 security)
// const md5 = require("md5");
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.set('view engine', 'ejs');

mongoose.set('strictQuery', true);
mongoose.connect("mongodb://0.0.0.0:27017/userDB", {useNewUrlParser: true});

const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

// commented out because in case of high level breach the .env file is vulnerable
// so we use md5 to hash passwords instead
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model("User", userSchema);

app.get('/', function(req, res) {
    res.render("home");
})

app.get('/login', function(req, res) {
    res.render("login");
})

app.get('/register', function(req, res) {
    res.render("register");
})

app.post("/register", function(req, res) {

    // instead of md5(req.body.password); we use bcrypt's hash method
    // and pass it user entered password and no. of salt rounds,
    // in callback function it takes the final hash generated after
    // mentioned no. of salt rounds which we can store in our database
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        const newUser = new User({
            email: req.body.username,
            password: hash
        });
    
        newUser.save(function(err) {
            if(!err){
                res.render("secrets");
            }else{
                console.log(err);
            }
        });
    })
    

})

app.post("/login", function(req, res) {

    const username = req.body.username;
    // const password = md5(req.body.password);
    const password = req.body.password;
    User.findOne({email: username}, function(err, foundUser) {
        if(!err){
            if(foundUser){

                // bcrypt.compare() takes in user entered password, second parameter
                // is the hash that was generated for the foundUser, so we tap into the
                // password field of foundUser which contains that hash in database
                // compare() method will compare both and in the callback function the
                // result will be passed which is boolean so we use it to check if they match
                // or not.
                
                bcrypt.compare(password, foundUser.password, function(err, result) {
                    if(result === true){
                        res.render("secrets");
                    }
                })
            }
        }else{
            console.log(err);
        }
    });
});

app.listen(3000, function() {
    console.log("Server started on port 3000");
})
