// check-db-data.js - Run this to check database data
const db = require('./src/config/db');
const mysql = require('mysql2/promise');

async function checkDatabase() {
  try {
    console.log('🔍 Checking Database Data...\n');

    // 1. Check documents table
    console.log('📄 Documents Table:');
    const [documents] = await db.query(`
      SELECT d.id, d.title, d.filename, d.filepath, d.mime_type, d.file_size, 
             d.uploaded_by, u.name as uploaded_by_name, d.uploaded_at, d.updated_at,
             d.current_version_id
      FROM documents d
      LEFT JOIN users u ON d.uploaded_by = u.id
      WHERE d.is_active = 1
      ORDER BY d.uploaded_at DESC
      LIMIT 10
    `);
    
    if (documents.length === 0) {
      console.log('   ❌ No documents found');
    } else {
      documents.forEach(doc => {
        console.log(`   📋 ID: ${doc.id} | Title: ${doc.title || doc.filename}`);
        console.log(`      File: ${doc.filename} | Size: ${Math.round(doc.file_size/1024)}KB`);
        console.log(`      Uploaded by: ${doc.uploaded_by_name || 'Unknown'} at: ${doc.uploaded_at}`);
        console.log(`      Current Version ID: ${doc.current_version_id || 'NULL'}\n`);
      });
    }

    // 2. Check document_versions table
    console.log('\n📚 Document Versions Table:');
    const [versions] = await db.query(`
      SELECT dv.id, dv.document_id, dv.version_number, dv.filename, dv.filepath,
             dv.mime_type, dv.file_size, dv.version_note, dv.created_by,
             u.name as created_by_name, dv.created_at
      FROM document_versions dv
      LEFT JOIN users u ON dv.created_by = u.id
      ORDER BY dv.document_id, dv.version_number DESC
      LIMIT 15
    `);

    if (versions.length === 0) {
      console.log('   ❌ No versions found');
    } else {
      versions.forEach(ver => {
        console.log(`   📜 DocID: ${ver.document_id} | Version: ${ver.version_number} | VersionID: ${ver.id}`);
        console.log(`      File: ${ver.filename} | Size: ${Math.round(ver.file_size/1024)}KB`);
        console.log(`      Created by: ${ver.created_by_name || 'Unknown'} at: ${ver.created_at}`);
        if (ver.version_note) console.log(`      Note: ${ver.version_note}`);
        console.log('');
      });
    }

    // 3. Check users table
    console.log('\n👥 Users Table:');
    const [users] = await db.query(`
      SELECT id, name, email, role_id 
      FROM users 
      ORDER BY id
      LIMIT 5
    `);

    if (users.length === 0) {
      console.log('   ❌ No users found');
    } else {
      users.forEach(user => {
        console.log(`   👤 ID: ${user.id} | Name: ${user.name} | Email: ${user.email} | Role: ${user.role_id}`);
      });
    }

    // 4. Summary
    console.log('\n📊 Summary:');
    const [docCount] = await db.query('SELECT COUNT(*) as count FROM documents WHERE is_active = 1');
    const [verCount] = await db.query('SELECT COUNT(*) as count FROM document_versions');
    const [userCount] = await db.query('SELECT COUNT(*) as count FROM users');
    
    console.log(`   Documents: ${docCount[0].count}`);
    console.log(`   Versions: ${verCount[0].count}`);
    console.log(`   Users: ${userCount[0].count}`);

    await db.end();
    console.log('\n✅ Database check completed!');

  } catch (error) {
    console.error('❌ Database Error:', error.message);
    console.error('Stack:', error.stack);
  }
}

// Run the check
checkDatabase();