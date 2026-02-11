// src/config/db.js
const mysql = require("mysql2/promise");
require("dotenv").config();

const pool = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "localdb",
  database: process.env.DB_NAME || "schl_dms",
  waitForConnections: true,
  connectionLimit: 10
});

module.exports = pool;
