const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bodyParser = require('body-parser')
const config = process.env;
const express = require("express");
const app = express();

app.use(cookieParser());
const verifyToken = (req, res, next) => {
  console.log(req.cookies, "cookies in middleware");

  const token =
    req.body.token || req.query.token || req.headers["x-access-token"];
  console.log(token);
  if (!token) {
    return res.status(403).send("A token is required for authentication");
  }
  try {
    const decoded = jwt.verify(token, config.TOKEN_KEY);
    req.user = decoded;
  } catch (err) {
    return res.status(401).send("Invalid Token");
  }
  return next();
};

module.exports = verifyToken;
