const express = require('express');
const router = express.Router();
const documentController = require('../controllers/document.controller');
const { authenticateToken } = require('../middleware/auth');
const upload = require('../middleware/upload');

router.post('/upload', authenticateToken, upload.single('file'), documentController.uploadDocument);
router.get('/', authenticateToken, documentController.getAllDocuments);
router.get('/download/:id', authenticateToken, documentController.downloadDocument);
router.delete('/:id', authenticateToken, documentController.deleteDocument);

module.exports = router;
