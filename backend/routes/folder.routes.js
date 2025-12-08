const express = require('express');
const router = express.Router();
const folderController = require('../controllers/folder.controller');
const { authenticateToken } = require('../middleware/auth');

router.get('/', authenticateToken, folderController.getAllFolders);
router.post('/', authenticateToken, folderController.createFolder);

module.exports = router;
