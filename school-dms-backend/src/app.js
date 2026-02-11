// src/app.js
const express = require("express");
const cors = require("cors");
const path = require("path");

const authRoutes = require("./routes/auth.routes");
const documentsRoutes = require("./routes/documents.routes");

const app = express();

// Relax CSP ONLY for development so Chrome DevTools + localhost requests work
if (process.env.NODE_ENV !== "production") {
  app.use((req, res, next) => {
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self' 'unsafe-inline' data: blob:; " +
      "connect-src 'self' http://localhost:4000 http://localhost:5173 ws://localhost:5173; " +
      "img-src 'self' data: blob:; " +
      "font-src 'self' data:;"
    );
    next();
  });
}


app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// serve uploaded files (downloads handled by controller but this helps)
app.use("/uploads", express.static(path.join(process.cwd(), "uploads")));

// API routes
app.use("/api/auth", authRoutes);
app.use("/api/documents", documentsRoutes);

// health
app.get("/health", (req, res) => res.json({ ok: true }));

// dev-only error handler: prints stack to console and returns a helpful JSON (remove or tighten for production)
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err && err.stack ? err.stack : err);
  res.status(err.status || 500).json({
    message: err.message || "Server error",
    // include stack only in dev
    stack: process.env.NODE_ENV === "production" ? undefined : err.stack
  });
});

module.exports = app;
