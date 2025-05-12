require("./utils.js")

require("dotenv").config();
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");

let saltRounds = 12

const port = process.env.PORT || 3000;

const app = express();


const expireTime = 1 * 60 * 60 * 1000;

const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const mongodbUser = process.env.MONGODB_USER;
const mongodbpw = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;


const node_session_secret = process.env.NODE_SESSION_SECRET;

var { database } = include("dbConnection");

const userCollection = database.db(mongodb_database).collection("Users");


app.set("view engine", "ejs");


app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodbUser}:${mongodbpw}@cluster0.yd3rf6r.mongodb.net/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
});



app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}));
app.use(express.static(__dirname + "/public"));


function isAdmin(req) {
    if (req.session.user_type == "admin") {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("notAuthorized");
        return;
    }
    else {
        next();
    }
}

function isValidSession(req){
    if(req.session.authenticated == true){
        return true;
    }
    return false;
} 
function sessionValidation(req, res, next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        console.log("session expired");
        res.redirect('/login');
    }
}

app.get("/", (req, res) => {
    let authenticated = req.session.authenticated;
    let name = req.session.name;
    res.render("index", { authenticated: authenticated, name: name });
    
});

app.get("/signUp", (req, res) => {
    res.render("signup");
});


app.post("/submitUser", async (req, res) => {
    let name = req.body.name;
    let username = req.body.username;
    let password = req.body.password;
    if (name === "" || username === "" || password === "") {
        res.render("submitError", { 
            name: name, 
            username: username, 
            password: password
        });
        return;
    }
    else {

        //Password validator
        const schema = Joi.object(
            {
                name: Joi.string().alphanum().max(20).required(),
                username: Joi.string().max(20).required(),
                password: Joi.string().max(20).required()
            });


        const validationResult = schema.validate({ name, username, password });
        if (validationResult.error != null) {
            console.log(validationResult.error);
            res.redirect("/signUp");
            return;
        }

        let hashedPass = await bcrypt.hashSync(password, saltRounds);
        req.session.authenticated = true;
        req.session.name = name;
        req.session.cookie.maxAge = expireTime;

        await userCollection.insertOne({ name: name, username: username, password: hashedPass, user_type:"normal" });
        console.log("Inserted user");

        res.redirect("/");
    }
});


app.get("/login", (req, res) => {

    let error = req.query.error;
    res.render("login", { error: error });

})

app.post("/loggingin", async (req, res) => {
    let username = req.body.username;
    let password = req.body.password;

    const schema = Joi.object(
        {
            username: Joi.string().max(20).required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ username, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login?error=SQL injection");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, name: 1, _id: 1, user_type: 1}).toArray();

    if (result.length != 1) {
        console.log("user not found");
        res.redirect("/login?error=user not found");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = username;
        req.session.name = result[0].name;
        req.session.cookie.maxAge = expireTime;
        req.session.user_type = result[0].user_type;

        res.redirect('/');
        return;
    }
    else {
        console.log("incorrect password");
        res.redirect("/login?error=incorrect password");
        return;
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

app.get("/members", sessionValidation, (req, res) => {
    let randomNum = Math.floor(Math.random() * 3) + 1;
    let name = req.session.name;
    res.render("members", { randomNum: randomNum, name: name });
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const users = await userCollection.find().project({ name: 1, username: 1, _id: 1, user_type: 1 }).toArray();
    console.log(users[0].user_type);
    res.render("admin", { users: users });
});

app.get("/updateUser", async (req, res) => {
    console.log("In update")
    let username = req.query.username;
    let user_type = req.query.user_type;
    console.log(username + "-" + user_type);
    const result = await userCollection.updateOne({username:username}, 
        {$set: {user_type:user_type}});
        console.log(result);
    res.redirect("/admin");
});

app.get("*", (req, res) => {
    res.status(404);
    res.render("404");
});
app.listen(port, () => {
    console.log(`Server running on local host ${port}`);
});