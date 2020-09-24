require('dotenv').config()
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const router = new express.Router();
const jwt = require("jsonwebtoken");

let corsOptions = {
    origin: "https://timetable.viaplanner.ca", // allow only viaplanner to use the api
    optionsSuccessStatus: 200,
};

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per 15 minutes, so 9 requests per seconds
});


router.get("/auth", [limiter, authenticateToken, cors(corsOptions)], (req, res) => {
    
    res.json("success")

})

router.post("/auth/login", [limiter, cors(corsOptions)], (req, res) => {
    const username = req.body.username;
    const user = {
        username,
    };

    const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
    res.json({ accessToken });
});

function authenticateToken (req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token == null) return res.sendStatus(401)

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user)=> {
        if(err) return res.sendStatus(403)
        req.user = user
        next()
    })
}
