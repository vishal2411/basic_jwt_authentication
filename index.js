require('dotenv').config(); // Load environment variables
const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const app = express();

// Middleware setup
app.use(helmet()); // Set various HTTP headers for security
app.use(cors()); // Enable CORS with default settings
app.use(bodyParser.json()); // Parse JSON bodies
app.use(bodyParser.urlencoded({ extended: true })); // Parse URL-encoded bodies

const secretkey = process.env.SECRET_KEY || "secretkey";

// Rate limiter setup
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 5, // Limit each IP to 5 requests per windowMs
    message: "Too many requests from this IP, please try again later."
});

app.get("/", (req, res) => {
    res.json({
        message: "Hello World API"
    });
});

app.post("/login", apiLimiter, (req, res) => {
    // Add input validation/sanitization as needed
    const user = {
        id: 1,
        username: "vishal",
        email: "vishal@gmail.com"
    };
    jwt.sign({ user }, secretkey, { expiresIn: '500s' }, (err, token) => {
        if (err) return res.status(500).json({ error: "Error signing token" });
        res.json({ token });
    });
});

app.post("/profile", verifyToken, apiLimiter, (req, res) => {
    jwt.verify(req.token, secretkey, (err, authData) => {
        if (err) return res.status(403).json({ message: "Invalid Token" });
        res.json({
            message: "Profile Accessed",
            authData
        });
    });
});

function verifyToken(req, res, next) {
    const bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader !== 'undefined') {
        const bearer = bearerHeader.split(' ');
        const bearerToken = bearer[1];
        req.token = bearerToken;
        next();
    } else {
        res.status(403).json({ message: "Token not provided" });
    }
}

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: "Something went wrong!" });
});

app.listen(5000, () => {
    console.log("APP Listening on port 5000");
});
