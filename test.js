require('dotenv').config();
const AWS = require('aws-sdk');

// Update AWS configuration from environment variables
AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION
});

const s3 = new AWS.S3();

const bucketName = process.env.AWS_BUCKET_NAME;

s3.listObjectsV2({ Bucket: bucketName }, (err, data) => {
  if (err) {
    console.error("Error connecting to bucket:", err);
  } else {
    // console.log(Bucket "${bucketName}" connection successful.);
    console.log("Objects in bucket:", data.Contents);
  }
});