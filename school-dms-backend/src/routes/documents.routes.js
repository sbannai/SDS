// src/routes/documents.routes.js
const express = require("express");
const router = express.Router();
const multer = require("multer");
const path = require("path");
const fs = require("fs");

// try both possible db file paths (../config/db or ../db) to avoid path-related crashes
let pool;
try {
  pool = require("../config/db");
} catch (e) {
  try {
    pool = require("../db");
  } catch (e2) {
    console.error("Could not require DB pool. Ensure src/config/db.js or src/db.js exists.", e, e2);
    // leave pool undefined — route handlers will return 500 with clear message
  }
}

const auth = require("../middleware/auth");
const documentsController = require("../controllers/documents.controller");

// ensure uploads dir exists (kept for backwards compatibility if other code uses it)
const uploadDir = path.join(__dirname, "..", "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// Use memory storage so files are available as req.file.buffer (no local disk)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 200 * 1024 * 1024 } // 200 MB
});


// quick test middleware — grants folder permissions so uploads won't be blocked
const folderPermissionMiddleware = (req, res, next) => {
  // you can refine these flags later; for now allow upload/view during testing
  req.folderPermission = { can_upload: true, can_view: true };
  next();
};


/*
  Upload route

  Frontend currently posts to: POST /api/documents/upload
  and sends form-data:
   - file (File)
   - documentId (optional)  --> treated as "upload new version" if provided
   - folderId (required for initial upload)
   - title, uploadNote, etc.

  Behavior kept backward-compatible:
   - if documentId present -> call uploadDocumentVersion (controller)
   - else -> call uploadDocument (controller)
 */
router.post("/upload", auth, folderPermissionMiddleware, upload.single("file"), async (req, res) => {  try {
    const documentId = req.body.documentId ? Number(req.body.documentId) : null;

    if (documentId) {
      req.params = req.params || {};
      req.params.id = String(documentId);
      return await documentsController.uploadDocumentVersion(req, res);
    }

    return await documentsController.uploadDocument(req, res);
  } catch (err) {
    console.error("Upload route error:", err);
    return res.status(500).json({ message: "Upload failed", error: err.message });
  }
});

// get total documents count
router.get("/count", auth, async (req, res) => {
  if (!pool) return res.status(500).json({ message: "DB pool not initialized on server" });
  try {
    const [rows] = await pool.query(
      `SELECT COUNT(*) as count FROM documents WHERE is_active = 1`
    );
    res.json({ count: rows[0].count });
  } catch (err) {
    console.error("count fetch error:", err && err.stack ? err.stack : err);
    res.status(500).json({ message: "Could not fetch count", error: err.message });
  }
});

// list documents in a specific folder or all documents
router.get("/", auth, folderPermissionMiddleware, async (req, res) => {
  if (req.query.folderId) {
    // If folderId is provided as query param, use folder-based listing
    req.params.id = req.query.folderId;
    return await documentsController.listDocumentsInFolder(req, res);
  }
  
  // Otherwise, list all documents for current user (shows documents from all folders)
  console.log("---- Documents route HIT (all folders) ----");
  if (!pool) {
    console.error("DB pool missing when listing documents");
    return res.status(500).json({ message: "DB not initialized on server" });
  }

  try {
    // ensure req.user exists
    if (!req.user || !req.user.id) {
      console.warn("documents list: missing req.user; returning 401");
      return res.status(401).json({ message: "Unauthorized - token missing or invalid" });
    }

    const userId = req.user.id;
    console.log("Listing all documents for userId =", userId);

    const [rows] = await pool.query(
      `SELECT d.id, d.folder_id, d.title, d.filename, d.filepath, d.mime_type, d.file_size, d.uploaded_by, u.name as uploaded_by_name, d.uploaded_at
       FROM documents d
       LEFT JOIN users u ON d.uploaded_by = u.id
       WHERE d.uploaded_by = ? AND d.is_active = 1
       ORDER BY d.uploaded_at DESC`,
      [userId]
    );
    console.log("All documents query returned rows:", rows && rows.length);
    res.json(rows);
  } catch (err) {
    console.error("documents list error:", err && err.stack ? err.stack : err);
    res.status(500).json({ message: "Could not fetch", error: err.message });
  }
});

// versions for a document
router.get("/:id/versions", auth, folderPermissionMiddleware, documentsController.listDocumentVersions);

// download specific version
router.get("/version/:versionId/download", auth, documentsController.downloadVersion);

// download current document
router.get("/:id/download", auth, documentsController.downloadDocument);

// upload new version for existing document
router.post("/:id/upload-version", auth, folderPermissionMiddleware, upload.single("file"), documentsController.uploadDocumentVersion);

// get document content for editing
router.get("/:id/content", auth, folderPermissionMiddleware, documentsController.getDocumentContent);

// save edited document as new version
router.post("/:id/edit", auth, folderPermissionMiddleware, documentsController.editDocument);

module.exports = router;