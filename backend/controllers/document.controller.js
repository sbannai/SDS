const db = require('../config/database');
const s3 = require('../config/aws');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const path = require('path');

exports.uploadDocument = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const { folder_id, description } = req.body;
    const file = req.file;
    const fileExtension = path.extname(file.originalname);
    const uniqueKey = `documents/${uuidv4()}${fileExtension}`;

    const checksum = crypto.createHash('sha256').update(file.buffer).digest('hex');

    const s3Params = {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: uniqueKey,
      Body: file.buffer,
      ContentType: file.mimetype,
      ServerSideEncryption: process.env.S3_ENCRYPTION
    };

    const s3Result = await s3.upload(s3Params).promise();

    const [result] = await db.query(
      `INSERT INTO documents 
       (document_name, original_filename, file_extension, file_size, mime_type, 
        s3_bucket, s3_key, s3_url, folder_id, uploaded_by, document_description, checksum)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [file.originalname, file.originalname, fileExtension, file.size, file.mimetype,
       process.env.S3_BUCKET_NAME, uniqueKey, s3Result.Location, folder_id,
       req.user.user_id, description || null, checksum]
    );

    await db.query(
      'INSERT INTO audit_logs (user_id, document_id, action, ip_address) VALUES (?, ?, ?, ?)',
      [req.user.user_id, result.insertId, 'upload', req.ip]
    );

    res.status(201).json({
      message: 'Document uploaded successfully',
      document_id: result.insertId
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Upload failed' });
  }
};

exports.getAllDocuments = async (req, res) => {
  try {
    const [documents] = await db.query(`
      SELECT d.*, u.full_name as uploaded_by_name, f.folder_name
      FROM documents d
      JOIN users u ON d.uploaded_by = u.user_id
      JOIN folders f ON d.folder_id = f.folder_id
      WHERE d.is_current_version = TRUE
      ORDER BY d.uploaded_at DESC
    `);
    res.json({ documents });
  } catch (error) {
    res.status(500).json({ error: 'Error fetching documents' });
  }
};

exports.downloadDocument = async (req, res) => {
  try {
    const [documents] = await db.query(
      'SELECT * FROM documents WHERE document_id = ?',
      [req.params.id]
    );

    if (documents.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const document = documents[0];
    const params = {
      Bucket: document.s3_bucket,
      Key: document.s3_key,
      Expires: 300
    };

    const url = await s3.getSignedUrlPromise('getObject', params);

    await db.query(
      'INSERT INTO audit_logs (user_id, document_id, action, ip_address) VALUES (?, ?, ?, ?)',
      [req.user.user_id, document.document_id, 'download', req.ip]
    );

    res.json({ download_url: url });
  } catch (error) {
    res.status(500).json({ error: 'Download failed' });
  }
};

exports.deleteDocument = async (req, res) => {
  try {
    const [documents] = await db.query(
      'SELECT * FROM documents WHERE document_id = ?',
      [req.params.id]
    );

    if (documents.length === 0) {
      return res.status(404).json({ error: 'Document not found' });
    }

    const document = documents[0];

    await s3.deleteObject({
      Bucket: document.s3_bucket,
      Key: document.s3_key
    }).promise();

    await db.query('DELETE FROM documents WHERE document_id = ?', [req.params.id]);

    res.json({ message: 'Document deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Delete failed' });
  }
};
