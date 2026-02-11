// src/middleware/auth.js
const jwt = require("jsonwebtoken");
require("dotenv").config();

module.exports = function (req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "No token" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Invalid token" });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // contains id, role_id, role_name, email
    next();
  } catch (err) {
    console.error("Auth verify error:", err && err.stack ? err.stack : err);
    return res.status(401).json({ message: "Invalid token" });
  }
};
