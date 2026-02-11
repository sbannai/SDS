// src/controllers/documents.controller.js
const fs = require("fs");
const path = require("path");
const db = require("../config/db");

// AWS S3
const s3 = require("../config/s3"); // your s3 client (must export S3Client)
const { PutObjectCommand, GetObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

// Office document parsing libraries
const mammoth = require("mammoth");
const XLSX = require("xlsx");

const BUCKET = process.env.S3_BUCKET || "dev-educhoice";
const S3_FOLDER = "SDS";
const PRESIGNED_URL_EXPIRES = 60 * 5; // 5 minutes

// helper - kept for compatibility if local copies are still used anywhere
function ensureDirSync(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// -------------------- listDocumentsInFolder --------------------
async function listDocumentsInFolder(req, res) {
  try {
    const folderId = Number(req.params.folderId || req.params.id || req.query.folderId);
    console.log("DEBUG: listDocumentsInFolder called. user:", req.user, "folderId:", folderId, "req.folderPermission:", req.folderPermission);

    if (!folderId) {
      console.warn("DEBUG: missing folderId");
      return res.status(400).json({ message: "Invalid folder id" });
    }

    const sql = `
      SELECT d.id, d.title, d.filename, d.filepath, d.mime_type, d.file_size, d.uploaded_by, u.name as uploaded_by_name, d.uploaded_at
      FROM documents d
      LEFT JOIN users u ON d.uploaded_by = u.id
      WHERE d.folder_id = ? AND d.is_active = 1
      ORDER BY d.uploaded_at DESC
    `;
    console.log("DEBUG: running SQL:", sql.replace(/\s+/g, " "), "params:", [folderId]);

    const [rows] = await db.query(sql, [folderId]);

    console.log("DEBUG: SQL returned rows:", rows && rows.length);
    return res.json(rows);
  } catch (err) {
    console.error("DEBUG: listDocumentsInFolder error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ message: "Server error", error: err && err.message ? err.message : String(err) });
  }
}

// -------------------- uploadDocument (initial upload) --------------------
async function uploadDocument(req, res) {
  try {
    const folderId = Number(req.body.folderId);
    if (!folderId) return res.status(400).json({ message: "folderId required" });

    if (!req.folderPermission?.can_upload) return res.status(403).json({ message: "Forbidden" });

    if (!req.file) return res.status(400).json({ message: "File required" });

    // Insert metadata placeholder into documents table
    const [result] = await db.query(
      `INSERT INTO documents (folder_id, title, filename, filepath, mime_type, file_size, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [folderId, req.body.title || req.file.originalname, req.file.originalname, null, req.file.mimetype, req.file.size, req.user?.id || null]
    );
    const documentId = result.insertId;

    // derive stored filename and S3 key
    const timestamp = Date.now();
    const originalName = req.file.originalname.replace(/\s+/g, "_");
    const storedFilename = `${timestamp}_${originalName}`;
    const s3Key = `${S3_FOLDER}/${documentId}/${storedFilename}`;

    // Upload to S3 (do NOT set ACL - bucket likely has ACLs disabled)
    const putCmd = new PutObjectCommand({
      Bucket: BUCKET,
      Key: s3Key,
      Body: req.file.buffer,
      ContentType: req.file.mimetype
    });

    await s3.send(putCmd);

    // S3 HTTP URL (public-format). If you want a different format (s3://...), change here.
    const s3HttpUrl = `https://${BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${encodeURI(s3Key)}`;

    // Update documents row with stored filename and filepath (store HTTP url)
    await db.query(
      `UPDATE documents SET filename = ?, filepath = ?, mime_type = ?, file_size = ? WHERE id = ?`,
      [storedFilename, s3HttpUrl, req.file.mimetype, req.file.size, documentId]
    );

    // Insert document_versions row (include filepath)
    const [verResult] = await db.query(
      `INSERT INTO document_versions (document_id, filename, filepath, mime_type, file_size, created_by) VALUES (?, ?, ?, ?, ?, ?)`,
      [documentId, storedFilename, s3HttpUrl, req.file.mimetype, req.file.size, req.user?.id || null]
    );

    // Generate presigned URL for immediate download/open (works whether object is public or not)
    const getCmd = new GetObjectCommand({ Bucket: BUCKET, Key: s3Key });
    const downloadUrl = await getSignedUrl(s3, getCmd, { expiresIn: PRESIGNED_URL_EXPIRES });

    const [[doc]] = await db.query(`SELECT * FROM documents WHERE id = ?`, [documentId]);

    // versionNumber for initial upload is 1
    const versionNumber = 1;

    return res.json({
      message: "Uploaded",
      document: doc,
      documentId,
      versionId: verResult.insertId,
      versionNumber,
      downloadUrl
    });
  } catch (err) {
    console.error("uploadDocument error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ message: "Upload failed", error: err && err.message ? err.message : String(err) });
  }
}

// -------------------- uploadDocumentVersion (new version) --------------------
async function uploadDocumentVersion(req, res) {
  try {
    const documentId = Number(req.params.id);
    if (!documentId) return res.status(400).json({ message: "Invalid document id" });
    if (!req.file) return res.status(400).json({ message: "File required" });

    if (!req.folderPermission?.can_upload) return res.status(403).json({ message: "Forbidden" });

    // derive stored filename and S3 key
    const timestamp = Date.now();
    const originalName = req.file.originalname.replace(/\s+/g, "_");
    const storedFilename = `${timestamp}_${originalName}`;
    const s3Key = `${S3_FOLDER}/${documentId}/${storedFilename}`;

    // Upload new version to S3 (no ACL)
    const putCmd = new PutObjectCommand({
      Bucket: BUCKET,
      Key: s3Key,
      Body: req.file.buffer,
      ContentType: req.file.mimetype
    });
    await s3.send(putCmd);

    const s3HttpUrl = `https://${BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${encodeURI(s3Key)}`;

    // find next version number
    const [rows] = await db.query(`SELECT COALESCE(MAX(version_number),0) as maxv FROM document_versions WHERE document_id = ?`, [documentId]);
    const nextVersion = (rows[0] && rows[0].maxv ? rows[0].maxv : 0) + 1;

    // insert version row with filepath
    const [result] = await db.query(
      `INSERT INTO document_versions (document_id, version_number, filename, filepath, mime_type, file_size, version_note, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [documentId, nextVersion, storedFilename, s3HttpUrl, req.file.mimetype || null, req.file.size || null, req.body.version_note || null, req.user?.id || null]
    );

    // update documents table
    await db.query(`UPDATE documents SET filename = ?, filepath = ?, mime_type = ?, file_size = ?, updated_at = NOW(), current_version_id = ? WHERE id = ?`,
      [storedFilename, s3HttpUrl, req.file.mimetype || null, req.file.size || null, result.insertId, documentId]);

    // presigned url for immediate download/open
    const getCmd = new GetObjectCommand({ Bucket: BUCKET, Key: s3Key });
    const downloadUrl = await getSignedUrl(s3, getCmd, { expiresIn: PRESIGNED_URL_EXPIRES });

    const [[version]] = await db.query(`SELECT * FROM document_versions WHERE id = ?`, [result.insertId]);
    return res.json({
      message: "Version uploaded",
      version,
      versionId: result.insertId,
      versionNumber: nextVersion,
      downloadUrl
    });
  } catch (err) {
    console.error("uploadDocumentVersion error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ message: "Upload failed", error: err && err.message ? err.message : String(err) });
  }
}

// -------------------- listDocumentVersions --------------------
async function listDocumentVersions(req, res) {
  try {
    const documentId = Number(req.params.id);
    if (!documentId) return res.status(400).json({ message: "Invalid document id" });
    if (!req.folderPermission?.can_view) return res.status(403).json({ message: "Forbidden" });

    const [rows] = await db.query(
      `SELECT dv.id, dv.version_number, dv.filename, dv.filepath, dv.mime_type, dv.file_size, dv.version_note, dv.created_by, dv.created_at, u.name as created_by_name
       FROM document_versions dv
       LEFT JOIN users u ON dv.created_by = u.id
       WHERE dv.document_id = ?
       ORDER BY dv.created_at DESC`,
      [documentId]
    );
    res.json(rows);
  } catch (err) {
    console.error("listDocumentVersions error:", err && err.stack ? err.stack : err);
    res.status(500).json({ message: "Failed to list versions", error: err && err.message ? err.message : String(err) });
  }
}

// -------------------- downloadVersion --------------------
async function downloadVersion(req, res) {
  try {
    const versionId = Number(req.params.versionId);
    if (!versionId) return res.status(400).json({ message: "Invalid version id" });

    const [rows] = await db.query(`SELECT document_id, filename, filepath FROM document_versions WHERE id = ?`, [versionId]);
    if (!rows.length) return res.status(404).json({ message: "Version not found" });

    const { document_id: documentId, filename } = rows[0];

    const [docRows] = await db.query(`SELECT folder_id FROM documents WHERE id = ?`, [documentId]);
    if (!docRows.length) return res.status(404).json({ message: "Document not found" });
    const folderId = docRows[0].folder_id;

    const [permRows] = await db.query(`SELECT can_view FROM role_folder_permissions WHERE role_id = ? AND folder_id = ?`, [req.user?.role_id, folderId]);
    if (!permRows.length || !permRows[0].can_view) return res.status(403).json({ message: "Forbidden" });

const s3Key = `${S3_FOLDER}/${documentId}/${filename}`;
    const getCmd = new GetObjectCommand({ Bucket: BUCKET, Key: s3Key });

    // Get the file from S3 and stream it directly
    const s3Response = await s3.send(getCmd);
    
    // Set appropriate headers for file download
    res.setHeader('Content-Type', s3Response.ContentType || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);
    res.setHeader('Access-Control-Allow-Origin', '*'); // CORS header
    
    // Stream the file content
    s3Response.Body.pipe(res);
    return;
  } catch (err) {
    console.error("downloadVersion error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ message: "Failed to download version", error: err && err.message ? err.message : String(err) });
  }
}

// -------------------- downloadDocument --------------------
async function downloadDocument(req, res) {
  try {
    const documentId = Number(req.params.id);
    if (!documentId) return res.status(400).json({ message: "Invalid document id" });

    const [rows] = await db.query(`SELECT folder_id, filename FROM documents WHERE id = ?`, [documentId]);
    if (!rows.length) return res.status(404).json({ message: "Document not found" });

    const { folder_id: folderId, filename } = rows[0];
    if (!filename) return res.status(404).json({ message: "No file available for this document" });

    const [permRows] = await db.query(`SELECT can_view FROM role_folder_permissions WHERE role_id = ? AND folder_id = ?`, [req.user?.role_id, folderId]);
    if (!permRows.length || !permRows[0].can_view) return res.status(403).json({ message: "Forbidden" });

    const s3Key = `${S3_FOLDER}/${documentId}/${filename}`;
    const getCmd = new GetObjectCommand({ Bucket: BUCKET, Key: s3Key });

    // Get the file from S3 and stream it directly
    const s3Response = await s3.send(getCmd);
    
    // Set appropriate headers for file download
    res.setHeader('Content-Type', s3Response.ContentType || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);
    res.setHeader('Access-Control-Allow-Origin', '*'); // CORS header
    
    // Stream the file content
    s3Response.Body.pipe(res);
    return;
  } catch (err) {
    console.error("downloadDocument error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ message: "Failed to download document", error: err && err.message ? err.message : String(err) });
  }
}

// -------------------- getDocumentContent --------------------
async function getDocumentContent(req, res) {
  try {
    const documentId = Number(req.params.id);
    if (!documentId) return res.status(400).json({ message: "Invalid document id" });

    // Get document and check permissions
    const [docRows] = await db.query(`SELECT folder_id, filename, filepath, mime_type FROM documents WHERE id = ? AND is_active = 1`, [documentId]);
    if (!docRows.length) return res.status(404).json({ message: "Document not found" });

    const { folder_id: folderId, filename, filepath, mime_type } = docRows[0];
    
    // Check view permissions
    const [permRows] = await db.query(`SELECT can_view FROM role_folder_permissions WHERE role_id = ? AND folder_id = ?`, [req.user?.role_id, folderId]);
    if (!permRows.length || !permRows[0].can_view) return res.status(403).json({ message: "Forbidden" });

    if (!filename || !filepath) {
      return res.json({ content: "", format: "text" });
    }

    // Try to read file from S3
    const s3Key = `${S3_FOLDER}/${documentId}/${filename}`;
    const getCmd = new GetObjectCommand({ Bucket: BUCKET, Key: s3Key });
    const response = await s3.send(getCmd);
    
    // Convert stream to buffer
    const chunks = [];
    for await (const chunk of response.Body) {
      chunks.push(chunk);
    }
    const buffer = Buffer.concat(chunks);

    let content = "";
    let format = "text";

    // Handle different file types
    if (mime_type === "application/vnd.openxmlformats-officedocument.wordprocessingml.document") {
      // .docx file
      try {
        const result = await mammoth.extractRawText({ buffer });
        content = result.value;
        format = "markdown";
      } catch (err) {
        console.error("Error extracting .docx content:", err);
        content = "# Document Content\n\nCould not extract content from this Word document.";
        format = "markdown";
      }
    } else if (mime_type === "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") {
      // .xlsx file
      try {
        const workbook = XLSX.read(buffer, { type: "buffer" });
        const firstSheet = workbook.Sheets[workbook.SheetNames[0]];
        const jsonData = XLSX.utils.sheet_to_json(firstSheet, { header: 1 });
        
        // Convert to markdown table
        content = "# Spreadsheet Data\n\n";
        jsonData.forEach((row, index) => {
          const rowText = row.map(cell => cell || "").join(" | ");
          content += `| ${rowText} |\n`;
          if (index === 0) {
            content += `| ${row.map(() => "---").join(" | ")} |\n`;
          }
        });
        format = "markdown";
      } catch (err) {
        console.error("Error extracting .xlsx content:", err);
        content = "# Spreadsheet Data\n\nCould not extract content from this Excel file.";
        format = "markdown";
      }
    } else if (mime_type === "application/vnd.openxmlformats-officedocument.presentationml.presentation") {
      // .pptx file - basic text extraction
      try {
        const zip = require('jszip');
        const zipFile = await zip.loadAsync(buffer);
        let slideText = "";
        
        // Extract text from slide XML files
        for (let i = 1; i <= 50; i++) { // Check up to 50 slides
          const slidePath = `ppt/slides/slide${i}.xml`;
          const slideFile = zipFile.files[slidePath];
          if (slideFile) {
            const slideContent = await slideFile.async("text");
            const textMatches = slideContent.match(/<a:t>(.*?)<\/a:t>/g);
            if (textMatches) {
              slideText += textMatches.map(match => match.replace(/<\/?a:t>/g, "")).join(" ") + "\n\n";
            }
          }
        }
        
        content = slideText || "# Presentation\n\nNo text content found in this PowerPoint file.";
        format = "markdown";
      } catch (err) {
        console.error("Error extracting .pptx content:", err);
        content = "# Presentation\n\nCould not extract content from this PowerPoint file.";
        format = "markdown";
      }
    } else {
      // Text-based files
      content = buffer.toString('utf-8');
      format = "text";
    }
    
    return res.json({ content, format });
  } catch (err) {
    console.error("getDocumentContent error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ message: "Failed to get document content", error: err && err.message ? err.message : String(err) });
  }
}

// -------------------- editDocument --------------------
async function editDocument(req, res) {
  try {
    const documentId = Number(req.params.id);
    const { content, note, format } = req.body;
    
    if (!documentId) return res.status(400).json({ message: "Invalid document id" });
    if (content === undefined || content === null) return res.status(400).json({ message: "Content is required" });

    // Get document and check permissions
    const [docRows] = await db.query(`SELECT folder_id, filename, mime_type FROM documents WHERE id = ? AND is_active = 1`, [documentId]);
    if (!docRows.length) return res.status(404).json({ message: "Document not found" });

    const { folder_id: folderId, filename, mime_type } = docRows[0];
    
    // Check if document is editable (non-PDF)
    if (mime_type === "application/pdf") {
      return res.status(400).json({ message: "PDF documents cannot be edited" });
    }

    // Check upload permissions (required for editing)
    if (!req.folderPermission?.can_upload) return res.status(403).json({ message: "Forbidden" });

    // Create new version with edited content
    const timestamp = Date.now();
    const originalName = filename ? filename.replace(/\s+/g, "_") : "edited_document.txt";
    const storedFilename = `${timestamp}_edited_${originalName}`;
    const s3Key = `${S3_FOLDER}/${documentId}/${storedFilename}`;

    let bodyContent;
    let finalMimeType = mime_type;

    // Convert edited content back to original format
    if (mime_type === "application/vnd.openxmlformats-officedocument.wordprocessingml.document") {
      // .docx file - save as plain text inside docx structure (simplified)
      bodyContent = Buffer.from(content, 'utf-8');
      finalMimeType = "text/plain"; // For simplicity, save as text
    } else if (mime_type === "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet") {
      // .xlsx file - convert markdown table back to CSV/Excel
      try {
        const lines = content.split('\n').filter(line => line.trim());
        const data = lines.map(line => 
          line.split('|').map(cell => cell.trim()).filter(cell => cell)
        ).filter(row => row.length > 0);
        
        const workbook = XLSX.utils.book_new();
        const worksheet = XLSX.utils.aoa_to_sheet(data);
        XLSX.utils.book_append_sheet(workbook, worksheet, "Sheet1");
        bodyContent = XLSX.write(workbook, { type: "buffer", bookType: "xlsx" });
      } catch (err) {
        console.error("Error creating .xlsx:", err);
        bodyContent = Buffer.from(content, 'utf-8');
        finalMimeType = "text/plain";
      }
    } else {
      // Text-based files
      bodyContent = content;
    }

    // Upload edited content to S3
    const putCmd = new PutObjectCommand({
      Bucket: BUCKET,
      Key: s3Key,
      Body: bodyContent,
      ContentType: finalMimeType || "text/plain"
    });
    await s3.send(putCmd);

    const s3HttpUrl = `https://${BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${encodeURI(s3Key)}`;

    // Find next version number
    const [verRows] = await db.query(`SELECT COALESCE(MAX(version_number),0) as maxv FROM document_versions WHERE document_id = ?`, [documentId]);
    const nextVersion = (verRows[0] && verRows[0].maxv ? verRows[0].maxv : 0) + 1;

    // Insert new version record
    const [result] = await db.query(
      `INSERT INTO document_versions (document_id, version_number, filename, filepath, mime_type, file_size, version_note, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [documentId, nextVersion, storedFilename, s3HttpUrl, finalMimeType || mime_type || "text/plain", bodyContent.length || Buffer.byteLength(content, 'utf8'), note || "Document edited via editor", req.user?.id || null]
    );

    // Update documents table
    await db.query(`UPDATE documents SET filename = ?, filepath = ?, mime_type = ?, file_size = ?, updated_at = NOW(), current_version_id = ? WHERE id = ?`,
      [storedFilename, s3HttpUrl, finalMimeType || mime_type || "text/plain", bodyContent.length || Buffer.byteLength(content, 'utf8'), result.insertId, documentId]);

    const [[version]] = await db.query(`SELECT * FROM document_versions WHERE id = ?`, [result.insertId]);
    
    return res.json({
      message: "Document saved as new version",
      version,
      versionId: result.insertId,
      versionNumber: nextVersion
    });
  } catch (err) {
    console.error("editDocument error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ message: "Failed to save document", error: err && err.message ? err.message : String(err) });
  }
}

module.exports = {
  listDocumentsInFolder,
  uploadDocument,
  uploadDocumentVersion,
  listDocumentVersions,
  downloadVersion,
  downloadDocument,
  getDocumentContent,
  editDocument
};
