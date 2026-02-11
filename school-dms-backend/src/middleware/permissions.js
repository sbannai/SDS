// src/middleware/permissions.js
const db = require("../config/db");

async function getFolderPermission(roleId, folderId) {
  const [rows] = await db.query(
    `SELECT can_view, can_upload, can_delete
       FROM role_folder_permissions
      WHERE role_id = ? AND folder_id = ?`,
    [roleId, folderId]
  );
  return rows[0] || null;
}

exports.requireFolderPermission = (permKey) => {
  return async (req, res, next) => {
    // accept folder id from /folder/:folderId, /:id, body or query
    const folderId = Number(req.params.folderId || req.params.id || req.body.folderId || req.query.folderId);
    if (!folderId || Number.isNaN(folderId)) {
      return res.status(400).json({ message: "folderId is required" });
    }

    const roleId = req.user?.role_id;
    if (!roleId) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    try {
      const perms = await getFolderPermission(roleId, folderId);
      if (!perms || !perms[permKey]) {
        return res.status(403).json({ message: "Forbidden" });
      }

      // controllers expect req.folderPermission (singular)
      req.folderPermission = perms;
      next();
    } catch (err) {
      console.error("permission middleware error:", err && err.stack ? err.stack : err);
      res.status(500).json({ message: "Server error" });
    }
  };
};
