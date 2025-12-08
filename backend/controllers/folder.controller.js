const db = require('../config/database');

exports.getAllFolders = async (req, res) => {
  try {
    const [folders] = await db.query('SELECT * FROM folders ORDER BY folder_name');
    res.json({ folders });
  } catch (error) {
    res.status(500).json({ error: 'Error fetching folders' });
  }
};

exports.createFolder = async (req, res) => {
  try {
    const { folder_name, parent_folder_id, category } = req.body;
    let folder_path = `/${folder_name}`;

    if (parent_folder_id) {
      const [parents] = await db.query(
        'SELECT folder_path FROM folders WHERE folder_id = ?',
        [parent_folder_id]
      );
      if (parents.length > 0) {
        folder_path = `${parents[0].folder_path}/${folder_name}`;
      }
    }

    const [result] = await db.query(
      'INSERT INTO folders (folder_name, parent_folder_id, folder_path, category, created_by) VALUES (?, ?, ?, ?, ?)',
      [folder_name, parent_folder_id, folder_path, category, req.user.user_id]
    );

    res.status(201).json({
      message: 'Folder created',
      folder_id: result.insertId
    });
  } catch (error) {
    res.status(500).json({ error: 'Folder creation failed' });
  }
};
