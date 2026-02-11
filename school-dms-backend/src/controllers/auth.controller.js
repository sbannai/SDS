// src/controllers/auth.controller.js
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../config/db");
require("dotenv").config();

async function login(req, res) {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: "Email and password required" });

  try {
    const [rows] = await db.query(
      `SELECT u.id, u.name, u.email, u.password_hash, r.id as role_id, r.name as role_name
       FROM users u
       LEFT JOIN roles r ON u.role_id = r.id
       WHERE u.email = ? AND u.is_active = 1`,
      [email]
    );

    if (!rows.length) return res.status(400).json({ message: "Invalid credentials" });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user.id, role_id: user.role_id, role_name: user.role_name, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: "8h"
    });

    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role_id: user.role_id, role_name: user.role_name }
    });
  } catch (err) {
    console.error("Login error", err && err.stack ? err.stack : err);
    res.status(500).json({ message: "Server error" });
  }
}

module.exports = { login };
