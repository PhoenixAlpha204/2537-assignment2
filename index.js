require("./utils.js");
require('dotenv').config();
const express = require('express');
const app = express();
const session = require('express-session');
const port = process.env.PORT || 3000;
const bcrypt = require('bcrypt');
const saltRounds = 12;
const MongoStore = require('connect-mongo');
const expireTime = 60 * 60 * 1000; //expires after 1 hour (minutes * seconds * millis)
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const node_session_secret = process.env.NODE_SESSION_SECRET;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
var { database } = include('databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');
var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/test`,
    crypto: {
        secret: mongodb_session_secret
    }
});
const Joi = require("joi");
const ObjectId = require('mongodb').ObjectId;
const navLinks = [
    {name: "Home", link: "/"},
    {name: "Sign Up", link: "/signup"},
    {name: "Log In", link: "/login"},
    {name: "Members", link: "/members"},
];
const url = require("url");

app.use("/images", express.static("./public"));

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    resave: false,
    saveUninitialized: false
}));

app.use("/", (req, res, next) => {
    app.locals.navLinks = navLinks;
    app.locals.currentUrl = url.parse(req.url).pathname;
    next();
});

function sessionValidation(req,res,next) {
    if (req.session.authenticated) {
        next();
    } else {
        res.redirect('/login');
    }
}

function adminAuthorization(req, res, next) {
    if (req.session.user_type != 'admin') {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

app.get('/', (req, res) => {
    res.render('index', { req: req });
});

app.get('/signup', (req, res) => {
    res.render('signup', { req: req, missing: req.query.missing });
});

app.post('/signupSubmit', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;
    if (!name) {
        res.redirect('/signup?missing=1');
    } else if (!email) {
        res.redirect('/signup?missing=2');
    } else if (!password) {
        res.redirect('/signup?missing=3');
    } else {
        const schema = Joi.object({
            name: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().max(30).required(),
            password: Joi.string().max(20).required()
        });
        const validationResult = schema.validate({ name, email, password });
        if (validationResult.error != null) {
            console.log(validationResult.error);
            res.redirect("/signup");
            return;
        }
        var hashedPassword = bcrypt.hashSync(password, saltRounds);
        await userCollection.insertOne({ name: name, email: email, password: hashedPassword, user_type: "user" });
        req.session.authenticated = true;
        req.session.name = name;
        req.session.user_type = "user";
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
    }
});

app.get('/login', (req, res) => {
    res.render('login', { missing : req.query.missing });
});

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;
    const schema = Joi.string().email().max(30).required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login?missing=1");
        return;
    }
    const result = await userCollection.find({ email: email })
        .project({ name: 1, email: 1, password: 1, user_type: 1, _id: 1 }).toArray();
    if (result.length != 1) {
        res.redirect("/login?missing=1");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
        return;
    } else {
        res.redirect("/login?missing=1");
        return;
    }
});

app.get('/members', sessionValidation, (req, res) => {
    res.render('members', { name: req.session.name });
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.redirect('/');
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const result = await userCollection.find().project({name: 1, _id: 1}).toArray();
    console.log(result);
    res.render("admin", {users: result});
});

app.get('/promote', sessionValidation, adminAuthorization, async (req, res) => {
    var id = req.query.id;
    await userCollection.updateOne({_id: new ObjectId(id)}, {$set: {user_type: 'admin'}});
    res.redirect('/admin');
});

app.get('/demote', sessionValidation, adminAuthorization, async (req, res) => {
    var id = req.query.id;
    await userCollection.updateOne({_id: new ObjectId(id)}, {$set: {user_type: 'user'}});
    res.redirect('/admin');
});

app.get("*", (req, res) => {
    res.status(404);
    res.render('404');
});

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 
