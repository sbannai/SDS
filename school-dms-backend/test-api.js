// test-api.js - Test API endpoints for document versions
const axios = require('axios');

const API_BASE = 'http://localhost:4000/api';
let authToken = '';

async function testAPI() {
  try {
    console.log('🧪 Testing Document Version API...\n');

    // 1. Login to get token
    console.log('🔐 Logging in...');
    const loginResponse = await axios.post(`${API_BASE}/auth/login`, {
      email: 'admin@gmail.com',
      password: 'admin123'
    });
    
    authToken = loginResponse.data.token;
    console.log('✅ Login successful! Token received.\n');

    const headers = {
      'Authorization': `Bearer ${authToken}`,
      'Content-Type': 'application/json'
    };

    // 2. Get all documents
    console.log('📄 Getting all documents...');
    const docsResponse = await axios.get(`${API_BASE}/documents`, { headers });
    const documents = docsResponse.data;
    
    console.log(`Found ${documents.length} documents:`);
    documents.forEach(doc => {
      console.log(`  📋 ID: ${doc.id} - ${doc.title || doc.filename}`);
    });
    console.log('');

    // 3. Test versions for document with ID 17 (has multiple versions)
    console.log('📚 Testing versions for Document ID 17...');
    try {
      const versionsResponse = await axios.get(`${API_BASE}/documents/17/versions`, { headers });
      const versions = versionsResponse.data;
      
      console.log(`Found ${versions.length} versions for document 17:`);
      versions.forEach(ver => {
        console.log(`  📜 Version ${ver.version_number || 'Unknown'} - ${ver.filename}`);
        console.log(`     Created: ${ver.created_at} | By: ${ver.created_by_name || 'Unknown'}`);
        if (ver.version_note) console.log(`     Note: ${ver.version_note}`);
      });
      console.log('');
    } catch (err) {
      console.log('❌ Error getting versions:', err.response?.data || err.message);
    }

    // 4. Test versions for document with ID 9 (also has versions)
    console.log('📚 Testing versions for Document ID 9...');
    try {
      const versionsResponse = await axios.get(`${API_BASE}/documents/9/versions`, { headers });
      const versions = versionsResponse.data;
      
      console.log(`Found ${versions.length} versions for document 9:`);
      versions.forEach(ver => {
        console.log(`  📜 Version ${ver.version_number || 'Unknown'} - ${ver.filename}`);
        console.log(`     Created: ${ver.created_at} | By: ${ver.created_by_name || 'Unknown'}`);
      });
      console.log('');
    } catch (err) {
      console.log('❌ Error getting versions:', err.response?.data || err.message);
    }

    // 5. Test documents count
    console.log('📊 Testing document count...');
    try {
      const countResponse = await axios.get(`${API_BASE}/documents/count`, { headers });
      console.log(`Total documents: ${countResponse.data.count}`);
    } catch (err) {
      console.log('❌ Error getting count:', err.response?.data || err.message);
    }

    console.log('\n✅ API Testing Complete!');

  } catch (error) {
    console.error('❌ API Test Error:', error.response?.data || error.message);
    if (error.code === 'ECONNREFUSED') {
      console.log('💡 Make sure backend server is running on port 4000');
    }
  }
}

// Run test
testAPI();