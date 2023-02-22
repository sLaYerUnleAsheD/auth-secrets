require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
// commented out because in case of high level breach the .env file is vulnerable
// so we use md5 to hash passwords instead
// const encrypt= require('mongoose-encryption');
const md5 = require("md5");

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

    const newUser = new User({
        email: req.body.username,
        password: md5(req.body.password)
    });

    newUser.save(function(err) {
        if(!err){
            res.render("secrets");
        }else{
            console.log(err);
        }
    });

})

app.post("/login", function(req, res) {

    const username = req.body.username;
    const password = md5(req.body.password);
    User.findOne({email: username}, function(err, foundUser) {
        if(!err){
            if(foundUser){
                if(foundUser.password === password){
                    res.render("secrets");
                }
            }
        }else{
            console.log(err);
        }
    });
});

app.listen(3000, function() {
    console.log("Server started on port 3000");
})
