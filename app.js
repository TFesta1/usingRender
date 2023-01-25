// https://cloud.mongodb.com/v2/63c57d18fed0090faae977cb#/clusters/connect?clusterId=Cluster0
const express = require("express")
const session = require('express-session')
const hbs = require("express-handlebars")//express handle bars
const mongoose = require("mongoose")
const passport = require('passport')
const localStrategy = require("passport-local").Strategy;
const bcrypt = require('bcrypt') //hashing passwords
const app = express();
// https://www.youtube.com/watch?v=W5Tb1MIeg-I&list=PLR8vUZDE6IeNNU4SclXYO3p34c2K1-H0h&index=2


const uri = "mongodb+srv://tfest:unsecurePass@cluster0.nptuzeh.mongodb.net/?retryWrites=true&w=majority"
mongoose.set('strictQuery', false); //To prep for the change, use setQuery to true
mongoose.connect(uri)
// mongoose.connect('mongodb//localhost:27017/node-auth')
const connection = mongoose.connection;
connection.once('open', () => {
    console.log("MongoDB database connection established sucessfully")
})

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    }
})

const User = mongoose.model("User", UserSchema)

// Middleware

// https://stackoverflow.com/questions/70008920/express-handlebars-error-handlebars-is-not-a-function
// Different from tutorial, name file extensions "Handlebars"
app.set("view engine", 'handlebars');
app.engine('handlebars', hbs.engine());

app.use(express.static(__dirname + "/public"));
// Would actually put these in an env package
app.use(session({
    secret: "verygoodsecret",
    resave: false,
    saveUninitialized: true
}));
app.use(express.urlencoded({ extended: false }))
app.use(express.json())

// Passport.json
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user, done){
    done(null, user.id)
})

passport.deserializeUser(function (id, done) {
    // setup user model
    User.findById(id, function (err, user){
        done(err, user);
    })
})

passport.use(new localStrategy(function (username, password, done) {
    User.findOne({ username: username }, function (err, user) {
        if (err) return done(err) 
        if (!user) return done(null, false, { message: "Incorrect username." })

        // If doesn't match, return error
        bcrypt.compare(password, user.password, function (err, res) {
            if (err) return done(err) 
            if (res === false) return done(null, false, { message: "Incorrect password."})
            
            // If works, pass the user to actually sign in
            return done(null, user);
        })
    })
}))

function isLoggedIn(req, res, next) {
    if(req.isAuthenticated()) return next();
    res.redirect("/login");
}

// If we are NOT authenticated
function isLoggedOut(req, res, next) {
    if(!req.isAuthenticated()) return next();
    res.redirect("/");
}

// Routes
app.get('/', isLoggedIn, (req, res) => {
    // Create an "index.handlebars" folder under views
    res.render("index", { title: "Home" })
})

// Showcasing some extra routes
app.get('/about', isLoggedIn, (req, res) => {
    res.render("index", { title: "About" })
})

// For putting up the login page
app.get("/login", isLoggedOut, (req, res) => {
    // If there's an error (passed as a port)
    const response = {
        title: "Login",
        error: req.query.error
    }
    
    res.render('login', response)
})

// After we hit "Login" we'll need a post req to handle this
app.post("/login", passport.authenticate("local", {
    successRedirect: '/',//choose where we want to go after a successful login
    failureRedirect: '/login?error=true'
}))

// Logout
app.get("/logout", function (req, res) {
    // req.logout(); --> changed
    req.logout(function(err) {
        if(err) return next(err)
        res.redirect("/")
    })
    
})

// Setup our admin user
app.get("/setup", async (req, res) => {
    const exists = await User.exists({ username: "admin" })
    if (exists) {
        console.log("Exists")
        res.redirect('/login')
        return;
    }

    // Generate a new "salt." This hashes the password
    bcrypt.genSalt(10, function(err, salt) {
        if (err) return next(err);
        bcrypt.hash("mypassword", salt, function(err, hash){
            if (err) return next(err);
            // Create a mongoose DB user
            const newAdmin = new User({
                username: "admin",
                password: hash
            });
            
            // Save it into the DB
            newAdmin.save();

            res.redirect("/login")
        })
    })
})




app.listen(3000, () => {
    console.log("Listening on port 3000")
})
