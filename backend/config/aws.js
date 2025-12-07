const AWS = require('aws-sdk');
require('dotenv').config();

// Configure AWS
AWS.config.update({
  region: process.env.AWS_REGION || 'us-east-1',
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});

// Create S3 instance
const s3 = new AWS.S3({
  signatureVersion: 'v4',
  params: { 
    Bucket: process.env.S3_BUCKET_NAME 
  }
});

// Test S3 connection
s3.listBuckets((err, data) => {
  if (err) {
    console.warn('⚠️  AWS S3 connection failed:', err.message);
    console.warn('Please configure AWS credentials in .env file');
  } else {
    console.log('✅ AWS S3 connected successfully');
  }
});

module.exports = s3;
