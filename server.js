// server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');


// AWS SDK v3 and multer-s3-v3 for S3 integration
const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const multer = require('multer');
const multerS3 = require('multer-s3-v3');

const app = express();

// ---------- PostgreSQL Setup ----------
const pool = new Pool({
  connectionString: process.env.PG_CONNECTION_STRING
});

pool.connect()
  .then(client => {
    console.log("✅ PostgreSQL Connected Successfully!");
    client.release();
  })
  .catch(err => {
    console.error("❌ Error connecting to PostgreSQL:", err);
    process.exit(1);
  });

// ---------- AWS S3 Client & Storage Configuration ----------
// Create an S3 client using environment variables
const s3Client = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

// Configure multer-s3 storage so that each tenant gets its own "folder" (prefix)
const s3Storage = multerS3({
  s3: s3Client,
  bucket: process.env.AWS_BUCKET_NAME,
  // Do not set an ACL if your bucket is configured for "Bucket owner enforced"
  key: (req, file, cb) => {
    // Ensure tenant is authenticated
    const tenantId = req.session.tenant.id;
    const filename = Date.now() + '-' + file.originalname;
    // The key is structured as "tenantId/filename"
    cb(null, `${tenantId}/${filename}`);
  },
});

// Create a multer instance that uses the S3 storage
const uploadToS3 = multer({
  storage: s3Storage,
});

// ---------- Default Email Template ----------
const defaultEmailTemplate = {
  "counters": {
    "u_column": 2,
    "u_row": 2,
    "u_content_heading": 1,
    "u_content_text": 1,
    "u_content_button": 1,
    "u_content_html": 1
  },
  "body": {
    "id": "RRlfnUq63V",
    "rows": [
      {
        "id": "MZFVoRRGQL",
        "cells": [1],
        "columns": [
          {
            "id": "LYIL7TxJV0",
            "contents": [
              {
                "id": "4aylgaquuy",
                "type": "heading",
                "values": {
                  "containerPadding": "10px",
                  "anchor": "",
                  "headingType": "h1",
                  "fontSize": "22px",
                  "textAlign": "center",
                  "lineHeight": "140%",
                  "linkStyle": {
                    "inherit": true,
                    "linkColor": "#0000ee",
                    "linkHoverColor": "#0000ee",
                    "linkUnderline": true,
                    "linkHoverUnderline": true
                  },
                  "hideDesktop": false,
                  "displayCondition": null,
                  "_styleGuide": null,
                  "_meta": {
                    "htmlID": "u_content_heading_1",
                    "htmlClassNames": "u_content_heading"
                  },
                  "selectable": true,
                  "draggable": true,
                  "duplicatable": true,
                  "deletable": true,
                  "hideable": true,
                  "text": "<span><strong>Thank you for your order!</strong></span>",
                  "_languages": {}
                }
              }
            ],
            "values": {
              "backgroundColor": "",
              "padding": "0px",
              "border": {},
              "borderRadius": "0px",
              "_meta": {
                "htmlID": "u_column_1",
                "htmlClassNames": "u_column"
              }
            }
          }
        ],
        "values": {
          "displayCondition": null,
          "columns": false,
          "_styleGuide": null,
          "backgroundColor": "",
          "columnsBackgroundColor": "",
          "backgroundImage": {
            "url": "",
            "fullWidth": true,
            "repeat": "no-repeat",
            "size": "custom",
            "position": "center",
            "customPosition": ["50%", "50%"]
          },
          "padding": "0px",
          "anchor": "",
          "hideDesktop": false,
          "_meta": {
            "htmlID": "u_row_1",
            "htmlClassNames": "u_row"
          },
          "selectable": true,
          "draggable": true,
          "duplicatable": true,
          "deletable": true,
          "hideable": true
        }
      },
      {
        "id": "jDzKAOB95k",
        "cells": [1],
        "columns": [
          {
            "id": "1IOiGNytn1",
            "contents": [
              {
                "id": "CGHePeBHpe",
                "type": "text",
                "values": {
                  "containerPadding": "10px",
                  "anchor": "",
                  "fontSize": "14px",
                  "textAlign": "center",
                  "lineHeight": "140%",
                  "linkStyle": {
                    "inherit": true,
                    "linkColor": "#0000ee",
                    "linkHoverColor": "#0000ee",
                    "linkUnderline": true,
                    "linkHoverUnderline": true
                  },
                  "hideDesktop": false,
                  "displayCondition": null,
                  "_styleGuide": null,
                  "_meta": {
                    "htmlID": "u_content_text_1",
                    "htmlClassNames": "u_content_text"
                  },
                  "selectable": true,
                  "draggable": true,
                  "duplicatable": true,
                  "deletable": true,
                  "hideable": true,
                  "text": "<p style=\"line-height: 140%;\">Please click the button below to download your digital product.</p>",
                  "_languages": {}
                }
              },
              {
                "id": "tCTWWxVaA9",
                "type": "button",
                "values": {
                  "href": {
                    "name": "web",
                    "values": {
                      "href": "{{download_link}}",
                      "target": "_blank"
                    },
                    "attrs": {
                      "href": "{{href}}",
                      "target": "{{target}}"
                    }
                  },
                  "buttonColors": {
                    "color": "#FFFFFF",
                    "backgroundColor": "#28a745",
                    "hoverColor": "#FFFFFF",
                    "hoverBackgroundColor": "#3AAEE0"
                  },
                  "size": {
                    "autoWidth": true,
                    "width": "100%"
                  },
                  "fontSize": "19px",
                  "lineHeight": "120%",
                  "textAlign": "center",
                  "padding": "10px 20px",
                  "border": {},
                  "borderRadius": "4px",
                  "hideDesktop": false,
                  "displayCondition": null,
                  "_styleGuide": null,
                  "containerPadding": "10px",
                  "anchor": "",
                  "_meta": {
                    "htmlID": "u_content_button_1",
                    "htmlClassNames": "u_content_button"
                  },
                  "selectable": true,
                  "draggable": true,
                  "duplicatable": true,
                  "deletable": true,
                  "hideable": true,
                  "text": "<strong><span style=\"line-height: 22.8px;\">Download Now</span></strong>",
                  "_languages": {},
                  "calculatedWidth": 176,
                  "calculatedHeight": 43
                }
              }
            ],
            "values": {
              "backgroundColor": "",
              "padding": "0px",
              "border": {},
              "borderRadius": "0px",
              "_meta": {
                "htmlID": "u_column_2",
                "htmlClassNames": "u_column"
              }
            }
          }
        ],
        "values": {
          "displayCondition": null,
          "columns": false,
          "_styleGuide": null,
          "backgroundColor": "",
          "columnsBackgroundColor": "",
          "backgroundImage": {
            "url": "",
            "fullWidth": true,
            "repeat": "no-repeat",
            "size": "custom",
            "position": "center"
          },
          "padding": "0px",
          "anchor": "",
          "hideDesktop": false,
          "_meta": {
            "htmlID": "u_row_2",
            "htmlClassNames": "u_row"
          },
          "selectable": true,
          "draggable": true,
          "duplicatable": true,
          "deletable": true,
          "hideable": true
        }
      }
    ],
    "headers": [],
    "footers": [],
    "values": {
      "_styleGuide": null,
      "popupPosition": "center",
      "popupWidth": "600px",
      "popupHeight": "auto",
      "borderRadius": "10px",
      "contentAlign": "center",
      "contentVerticalAlign": "center",
      "contentWidth": "500px",
      "fontFamily": {
        "label": "Arial",
        "value": "arial,helvetica,sans-serif"
      },
      "textColor": "#000000",
      "popupBackgroundColor": "#FFFFFF",
      "popupBackgroundImage": {
        "url": "",
        "fullWidth": true,
        "repeat": "no-repeat",
        "size": "cover",
        "position": "center"
      },
      "popupOverlay_backgroundColor": "rgba(0, 0, 0, 0.1)",
      "popupCloseButton_position": "top-right",
      "popupCloseButton_backgroundColor": "#DDDDDD",
      "popupCloseButton_iconColor": "#000000",
      "popupCloseButton_borderRadius": "0px",
      "popupCloseButton_margin": "0px",
      "popupCloseButton_action": {
        "name": "close_popup",
        "attrs": {
          "onClick": "document.querySelector('.u-popup-container').style.display = 'none';"
        }
      },
      "language": {},
      "backgroundColor": "#F7F8F9",
      "preheaderText": "",
      "linkStyle": {
        "body": true,
        "linkColor": "#0000ee",
        "linkHoverColor": "#0000ee",
        "linkUnderline": true,
        "linkHoverUnderline": true
      },
      "backgroundImage": {
        "url": "",
        "fullWidth": true,
        "repeat": "no-repeat",
        "size": "custom",
        "position": "center"
      },
      "_meta": {
        "htmlID": "u_body",
        "htmlClassNames": "u_body"
      }
    }
  },
  "schemaVersion": 18,


  html: `<html>
  <body style="font-family: Arial, sans-serif; padding: 20px;">
    <h2>Thank you for your order!</h2>
    <p>Please click the button below to download your digital product.</p>
    <p>
      <a href="{{download_link}}" style="display: inline-block; background: #28a745; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-size: 16px;">
        Download Now
      </a>
    </p>
  </body>
</html>`
};

// ---------- Middleware & Session ----------
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'secret-key',
  resave: false,
  saveUninitialized: false
}));

// Serve static CSS and public files
app.use('/css', express.static(path.join(__dirname, 'public/css')));

// ---------- Authentication & Multi‑Tenant Login ---------- //

// Render login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Render sign-up page
app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

// Process Sign-Up – new tenants register their shop details

app.post('/signup', async (req, res) => {
  let { username, password, shopify_store_url, shopify_api_password } = req.body;

  try {
    let refinedShopUrl = shopify_store_url
      .replace(/https?:\/\//, '') 
      .replace(/\/$/, '') 
      .toLowerCase(); 

    if (!/^[a-z0-9-]+\.myshopify\.com$/.test(refinedShopUrl)) {
      return res.redirect('/signup?error=Invalid Shopify store URL. Use <storename>.myshopify.com');
    }

    const existingTenant = await pool.query(
      "SELECT id FROM tenants WHERE shopify_store_url = $1",
      [refinedShopUrl]
    );

    if (existingTenant.rows.length > 0) {
      return res.redirect('/signup?message=Shop already exists. Redirecting to login...');
    }

    // Hash both passwords before storing
    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedApiPassword = await bcrypt.hash(shopify_api_password, 10);

    const result = await pool.query(
      "INSERT INTO tenants (username, password, shopify_store_url, shopify_api_password) VALUES ($1, $2, $3, $4) RETURNING *",
      [username, hashedPassword, refinedShopUrl, hashedApiPassword]
    );

    const tenant = result.rows[0];

    await pool.query(
      "INSERT INTO email_templates (tenant_id, design, html) VALUES ($1, $2, $3)",
      [tenant.id, JSON.stringify(defaultEmailTemplate.design), defaultEmailTemplate.html]
    );

    res.redirect('/login?message=Account created successfully! Please log in.');
  } catch (err) {
    console.error(err);
    res.redirect('/signup?error=Error signing up. Please try again.');
  }
});

// Process Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM tenants WHERE username = $1",
      [username]
    );

    if (result.rows.length) {
      const tenant = result.rows[0];

      // Compare hashed password
      const passwordMatch = await bcrypt.compare(password, tenant.password);
      if (passwordMatch) {
        req.session.tenant = tenant;
        return res.redirect('/admin/home');
      }
    }

    res.send("Invalid credentials");
  } catch (err) {
    console.error(err);
    res.status(500).send("Database error");
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Middleware to protect admin routes
function ensureAuthenticated(req, res, next) {
  if (req.session && req.session.tenant) {
    next();
  } else {
    res.redirect('/login');
  }
}

// ---------- Admin Pages (Protected) ----------
app.get('/admin/home', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html'));
});
app.get('/admin/email-editor', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'email-editor.html'));
});
app.get('/admin/smtp', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'smtp.html'));
});
app.get('/admin/assets', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'assets.html'));
});
app.get('/admin/products', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'products.html'));
});
app.get('/admin/orders', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin', 'orders.html'));
});

// ---------- Additional API Endpoints ---------- //

// Return current tenant details
app.get('/admin/api/tenant', ensureAuthenticated, async (req, res) => {
  res.json({ tenant: req.session.tenant });
});

// Return today's stats for the tenant
app.get('/admin/api/stats', ensureAuthenticated, async (req, res) => {
  const tenantId = req.session.tenant.id;
  const today = new Date().toISOString().slice(0,10);
  try {
    const result = await pool.query(
      "SELECT emails_sent, orders_served FROM stats WHERE tenant_id = $1 AND date = $2",
      [tenantId, today]
    );
    if (result.rows.length) {
      res.json(result.rows[0]);
    } else {
      res.json({ emails_sent: 0, orders_served: 0 });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "DB error" });
  }
});

// ---------- API Endpoints for Tenant Settings ---------- //

// Email Template Endpoints – stored in email_templates table
app.get('/admin/api/email-template', ensureAuthenticated, async (req, res) => {
  try {
    const tenantId = req.session.tenant.id;
    const result = await pool.query(
      "SELECT design, html FROM email_templates WHERE tenant_id = $1",
      [tenantId]
    );
    let template;
    if (result.rows.length === 0 || !result.rows[0].design) {
      template = defaultEmailTemplate;
    } else {
      template = result.rows[0];
      if (typeof template.design === 'string') {
        try {
          template.design = JSON.parse(template.design);
        } catch (e) {
          console.error("Error parsing design JSON from DB:", e);
          template.design = defaultEmailTemplate.design;
        }
      }
      if (!template.html) {
        template.html = defaultEmailTemplate.html;
      }
    }
    console.log("Fetched email template for tenant", tenantId, template);
    res.json({ template });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/admin/api/email-template', ensureAuthenticated, async (req, res) => {
  try {
    const tenantId = req.session.tenant.id;
    const { design, html } = req.body;
    const result = await pool.query(
      "SELECT id FROM email_templates WHERE tenant_id = $1",
      [tenantId]
    );
    if (result.rows.length) {
      await pool.query(
        "UPDATE email_templates SET design = $1, html = $2, updated_at = NOW() WHERE tenant_id = $3",
        [JSON.stringify(design), html, tenantId]
      );
      res.json({ message: 'Template updated successfully' });
    } else {
      await pool.query(
        "INSERT INTO email_templates (tenant_id, design, html) VALUES ($1, $2, $3)",
        [tenantId, JSON.stringify(design), html]
      );
      res.json({ message: 'Template saved successfully' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// SMTP Settings Endpoints – stored in smtp_settings table
app.get('/admin/api/smtp', ensureAuthenticated, async (req, res) => {
  try {
    const tenantId = req.session.tenant.id;
    const result = await pool.query(
      "SELECT host, port, smtp_user as \"user\", pass FROM smtp_settings WHERE tenant_id = $1",
      [tenantId]
    );
    res.json({ smtp: result.rows[0] || null });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

app.post('/admin/api/smtp', ensureAuthenticated, async (req, res) => {
  try {
    const tenantId = req.session.tenant.id;
    const { host, port, user, pass } = req.body;
    const result = await pool.query(
      "SELECT id FROM smtp_settings WHERE tenant_id = $1",
      [tenantId]
    );
    if (result.rows.length) {
      await pool.query(
        "UPDATE smtp_settings SET host = $1, port = $2, smtp_user = $3, pass = $4, updated_at = NOW() WHERE tenant_id = $5",
        [host, port, user, pass, tenantId]
      );
      res.json({ message: 'SMTP settings updated successfully' });
    } else {
      await pool.query(
        "INSERT INTO smtp_settings (tenant_id, host, port, smtp_user, pass) VALUES ($1, $2, $3, $4, $5)",
        [tenantId, host, port, user, pass]
      );
      res.json({ message: 'SMTP settings saved successfully' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'DB error' });
  }
});

// Verify SMTP connection


app.post('/admin/api/smtp/test', ensureAuthenticated, async (req, res) => {
  try {
    // Get SMTP settings from the database
    const tenantId = req.session.tenant.id;
    const result = await pool.query(
      "SELECT host, port, smtp_user AS user, pass FROM smtp_settings WHERE tenant_id = $1",
      [tenantId]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: "No SMTP settings found." });
    }

    const { host, port, user, pass } = result.rows[0];

    // Create a transporter for connection testing
    const transporter = nodemailer.createTransport({
      host: host,
      port: port,
      secure: port == 465, // True for SSL (port 465), false otherwise
      auth: { user, pass }
    });

    // Verify connection without sending an email
    transporter.verify((error, success) => {
      if (error) {
        console.error("SMTP Connection Failed:", error);
        return res.status(500).json({ success: false, message: "SMTP connection failed.", error: error.message });
      }
      console.log("SMTP Connection Successful!");
      return res.json({ success: true, message: "SMTP connection successful!" });
    });

  } catch (error) {
    console.error("SMTP Test Error:", error);
    res.status(500).json({ success: false, message: "Internal Server Error", error: error.message });
  }
});


// ---------- File Upload & Assets API (Protected) ----------
// Instead of using local persistent directories, we now use S3.
// Endpoint: Upload a file to S3 and save its metadata to the assets table.
// Endpoint: Upload a file to S3 and save its metadata to the assets table.
app.post('/api/upload', ensureAuthenticated, uploadToS3.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: 'No file uploaded' });
  }
  try {
    const tenantId = req.session.tenant.id;
    const s3Key = req.file.key;         // e.g. "tenantId/filename"
    const fileUrl = req.file.location;   // The public URL returned by multer-s3-v3
    const fileSize = req.file.size;

    // Save file metadata into the assets table.
    const result = await pool.query(
      "INSERT INTO assets (tenant_id, s3_key, file_url, file_size) VALUES ($1, $2, $3, $4) RETURNING *",
      [tenantId, s3Key, fileUrl, fileSize]
    );
    res.json({ message: 'File uploaded successfully', asset: result.rows[0] });
  } catch (err) {
    console.error("Error saving asset metadata:", err);
    res.status(500).json({ message: "File uploaded but failed to save metadata" });
  }
});

// Endpoint: List uploaded files for the current tenant (by querying the assets table)
app.get('/api/uploads', ensureAuthenticated, async (req, res) => {
  const tenantId = req.session.tenant.id;
  try {
    const result = await pool.query(
      "SELECT * FROM assets WHERE tenant_id = $1 ORDER BY uploaded_at DESC",
      [tenantId]
    );
    res.json({ files: result.rows });
  } catch (err) {
    console.error("Error fetching assets:", err);
    res.status(500).json({ error: "Error fetching assets" });
  }
});


// Import DeleteObjectCommand from AWS SDK v3 at the top (if not already imported)
const { DeleteObjectCommand } = require('@aws-sdk/client-s3');

// Endpoint: Delete an asset from S3 and the assets table.
// Expects a query parameter "s3_key" which is the S3 file key.
app.delete('/api/delete-asset', ensureAuthenticated, async (req, res) => {
  const { s3_key } = req.query;
  if (!s3_key) {
    return res.status(400).json({ message: "Missing s3_key parameter" });
  }
  try {
    // Delete the file from S3
    const deleteCommand = new DeleteObjectCommand({
      Bucket: process.env.AWS_BUCKET_NAME,
      Key: s3_key
    });
    await s3Client.send(deleteCommand);
    
    // Delete asset metadata from the database
    await pool.query("DELETE FROM assets WHERE s3_key = $1 AND tenant_id = $2", [s3_key, req.session.tenant.id]);
    res.json({ message: "Asset deleted successfully" });
  } catch (err) {
    console.error("Error deleting asset:", err);
    res.status(500).json({ message: "Error deleting asset" });
  }
});


// ---------- Secure Link Endpoint ----------
// Generate a temporary, secure (presigned) URL for a file stored in S3.
// Secure Link Endpoint: Generate a presigned URL valid for 24 hours
app.get('/secure-file', async (req, res) => {
  const key = req.query.key;
  if (!key) {
    return res.status(400).json({ error: "Missing 'key' query parameter" });
  }
  
  const command = new GetObjectCommand({
    Bucket: process.env.AWS_BUCKET_NAME,
    Key: key,
  });
  
  try {
    // Generate a presigned URL valid for 24 hours (86400 seconds)
    const url = await getSignedUrl(s3Client, command, { expiresIn: 86400 });
    res.json({ url });
  } catch (error) {
    console.error("Error generating signed URL:", error);
    res.status(500).json({ error: "Error generating secure link" });
  }
});

// ---------- Shopify Products & Attach File APIs (Protected) ----------
app.get('/api/products', ensureAuthenticated, async (req, res) => {
  try {
    const tenant = req.session.tenant;
    const response = await axios.get(`https://${tenant.shopify_store_url}/admin/api/2024-01/products.json`, {
      headers: {
        'X-Shopify-Access-Token': tenant.shopify_api_password,
        'Content-Type': 'application/json'
      }
    });
    res.json(response.data.products);
  } catch (err) {
    console.error("Error fetching products:", err.response?.data || err.message);
    res.status(500).json({ error: 'Error fetching products' });
  }
});

// Endpoint: Attach an S3 file to a Shopify product as a metafield, supporting multiple assets
app.post('/api/attach-file', ensureAuthenticated, async (req, res) => {
  let { productId, fileUrls } = req.body;
  try {
    const tenant = req.session.tenant;
    
    // Ensure fileUrls is an array
    if (!Array.isArray(fileUrls)) {
      fileUrls = [fileUrls];
    }
    
    // Process each asset URL
    fileUrls = fileUrls.map(url => {
      // If the item is an object, extract its s3_key
      if (typeof url === 'object' && url.s3_key) {
        url = url.s3_key;
      }
      // Remove the unwanted prefix if present
      if (typeof url === 'string' && url.startsWith("uploads/")) {
        url = url.replace(/^uploads\//, '');
      }
      return url;
    });
    
    // Fetch existing metafields for the product
    const metafieldsRes = await axios.get(`https://${tenant.shopify_store_url}/admin/api/2024-01/products/${productId}/metafields.json`, {
      headers: {
        'X-Shopify-Access-Token': tenant.shopify_api_password,
        'Content-Type': 'application/json'
      }
    });
    const metafields = metafieldsRes.data.metafields;
    let digitalField = metafields.find(field => field.namespace === 'digital_download' && field.key === 'digital_file');
    
    let newValue;
    if (digitalField) {
      try {
        // Attempt to parse the existing value as JSON
        const currentArray = JSON.parse(digitalField.value);
        if (Array.isArray(currentArray)) {
          newValue = JSON.stringify([...currentArray, ...fileUrls]);
        } else {
          newValue = JSON.stringify([digitalField.value, ...fileUrls]);
        }
      } catch (e) {
        // If parsing fails, assume a comma-separated string and convert it
        const currentArray = digitalField.value.split(',').map(s => s.trim()).filter(s => s);
        newValue = JSON.stringify([...currentArray, ...fileUrls]);
      }
    } else {
      // No existing metafield: create one with the array of fileUrls
      newValue = JSON.stringify(fileUrls);
    }
    
    // Update (or create) the metafield on the product.
    // We set the metafield type to "json_string" so that Shopify treats the value as JSON.
    const response = await axios.put(`https://${tenant.shopify_store_url}/admin/api/2024-01/products/${productId}.json`, {
      product: {
        id: productId,
        metafields: [{
          key: "digital_file",
          value: newValue,
          type: "json_string",
          namespace: "digital_download"
        }]
      }
    }, {
      headers: {
        'X-Shopify-Access-Token': tenant.shopify_api_password,
        'Content-Type': 'application/json'
      }
    });
    
    res.json(response.data);
    
  } catch (error) {
    console.error("Error attaching file to product:", error.response?.data || error.message);
    res.status(500).json({ error: 'Error attaching file to product' });
  }
});

// ---------- Order Details API Endpoints ---------- //
// Save order details (triggered from a webhook)
app.post('/admin/api/order', ensureAuthenticated, async (req, res) => {
  const tenantId = req.session.tenant.id;
  const { order_number, ordered_date, customer_name, customer_email, shopify_customer_url, latest_dispatched_email } = req.body;
  try {
    await pool.query(
      "INSERT INTO orders (tenant_id, order_number, ordered_date, customer_name, customer_email, shopify_customer_url, latest_dispatched_email) VALUES ($1, $2, $3, $4, $5, $6, $7)",
      [tenantId, order_number, ordered_date, customer_name, customer_email, shopify_customer_url, latest_dispatched_email]
    );
    res.json({ message: "Order saved successfully" });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: "DB error" });
  }
});

// Get all orders for the current tenant
app.get('/admin/api/orders', ensureAuthenticated, async (req, res) => {
  const tenantId = req.session.tenant.id;
  try {
    const result = await pool.query(
      "SELECT * FROM orders WHERE tenant_id = $1 ORDER BY ordered_date DESC",
      [tenantId]
    );
    res.json({ orders: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "DB error" });
  }
});
// Get orders based on filter (last 24 hours, 7 days, or 30 days)
app.get('/admin/api/orders/filter', ensureAuthenticated, async (req, res) => {
  const tenantId = req.session.tenant.id;
  const { period } = req.query; // Get filter from query params (e.g., ?period=7)

  let dateRangeQuery = "";

  if (period === "24") {
    dateRangeQuery = "AND ordered_date >= NOW() - INTERVAL '1 day'";
  } else if (period === "7") {
    dateRangeQuery = "AND ordered_date >= NOW() - INTERVAL '7 days'";
  } else if (period === "30") {
    dateRangeQuery = "AND ordered_date >= NOW() - INTERVAL '30 days'";
  }

  try {
    const result = await pool.query(
      `SELECT * FROM orders WHERE tenant_id = $1 ${dateRangeQuery} ORDER BY ordered_date DESC`,
      [tenantId]
    );
    res.json({ orders: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "DB error" });
  }
});



// ---------- In-Memory Delivery & Download Endpoints (Public) ----------
const downloadTokens = {}; // For production, consider persisting these tokens in your DB.
// Set expiry to 1 year (31536000000 ms); adjust as needed.
function generateDownloadToken(orderId, fileUrl) {
  const token = crypto.randomBytes(16).toString('hex');
  downloadTokens[token] = {
    orderId,
    fileUrl,
    expires: Date.now() + 31536000000, // 1 year in milliseconds
    downloadsLeft: 100
  };
  return token;
  
}





app.get('/download/:token', async (req, res) => {
  const tokenParam = req.params.token;
  // Query the DB for token data; adjust table/column names as needed.
  const result = await pool.query(
    "SELECT file_url, tenant_id FROM order_downloads WHERE token = $1",
    [tokenParam]
  );
  if (result.rows.length === 0) {
    return res.status(404).send('Invalid download link.');
  }
  const tokenData = result.rows[0];
  // if (Date.now() > new Date(tokenData.expires).getTime()) {
  //   return res.status(403).send('Download link expired.');
  // }
  // if (tokenData.downloads_left <= 0) {
  //   return res.status(403).send('Download limit exceeded.');
  // }
  // Decrement downloads_left in the DB.
  // await pool.query(
  //   "UPDATE order_downloads SET downloads_left = downloads_left - 1 WHERE token = $1",
  //   [tokenParam]
  // );
  // await pool.query(
  //   "INSERT INTO activity_logs (tenant_id, event_type, message) VALUES ($1, $2, $3)",
  //   [tenant_id.id, 'Download Initiated', `Customer initiated download for token: ${req.params.token}`]
  // );

  // Serve the file: if file_url is a full URL, redirect; else stream from S3.
  if (tokenData.file_url.startsWith('http')) {
    return res.redirect(tokenData.file_url);
  } else {
    const command = new GetObjectCommand({
      Bucket: process.env.AWS_BUCKET_NAME,
      Key: tokenData.file_url,
    });
    try {
      const data = await s3Client.send(command);
      const filename = tokenData.file_url.split('/').pop();
      res.attachment(filename);
      data.Body.pipe(res);
    } catch (err) {
      console.error("Error fetching file from S3:", err);
      res.status(500).send('Error fetching file from S3.');
    }
  }
});


  

// ---------- Improved Custom Order Delivery Page (Public) ----------
const orderDeliveries = {};

// ---------- GET Order Delivery Page (Public) ----------
app.get('/orders/:orderId', async (req, res) => {
  const orderId = req.params.orderId;
  let result = await pool.query(
    "SELECT product_id, product_name, file_url, token FROM order_downloads WHERE order_number = $1",
    [orderId]
  );
  // If no records are found by short order number, try using big order id.
  if (result.rows.length === 0) {
    result = await pool.query(
      "SELECT product_id, product_name, file_url, token FROM order_downloads WHERE big_order_id = $1",
      [orderId]
    );
  }

  if (result.rows.length === 0) {
    return res.status(404).send('No digital products found for this order.');
  }

  // Group rows by product_id so that one card is created per product.
  const groupedProducts = {};
  result.rows.forEach(item => {
    if (!groupedProducts[item.product_id]) {
      groupedProducts[item.product_id] = {
        product_name: item.product_name,
        assets: []
      };
    }
    groupedProducts[item.product_id].assets.push({
      file_url: item.file_url,
      token: item.token
    });
  });

  // Generate HTML: one card per product with each asset having a small download icon button and file name.
  const productsHtml = Object.values(groupedProducts).map(product => {
    const assetsHtml = product.assets.map(asset => {
      // Extract a clean file name from the file_url
      const fileName = asset.file_url.split('/').pop();
      return `
        <div class="asset-item" style="display: flex; align-items: center; gap: 5px; margin-top: 5px;">
          <button class="download-icon-btn" onclick="window.location.href='/download/${asset.token}'" title="Download">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
              <polyline points="7 10 12 15 17 10"></polyline>
              <line x1="12" y1="15" x2="12" y2="3"></line>
            </svg>
          </button>
          <span class="asset-filename" style="font-size: 13px; color: #64748b;">${fileName}</span>
        </div>
      `;
    }).join('');

    return `
      <div class="product-card">
        <h3>${product.product_name}</h3>
        <p>Your digital assets:</p>
        <div class="asset-buttons">
          ${assetsHtml}
        </div>
      </div>
    `;
  }).join('');

  res.send(`
    <html>
      <head>
        <title>Order ${orderId} - Digital Delivery</title>
        <link rel="stylesheet" type="text/css" href="/css/style.css">
        <style>
          .order-container { max-width: 800px; margin: 0 auto; padding: 20px; background: #fff; }
          .order-header { text-align: center; margin-bottom: 20px; }
          .product-card { border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-radius: 5px; }
          .download-icon-btn { background: none; border: none; cursor: pointer; }
          .download-icon-btn svg { transition: transform 0.2s ease; }
          .download-icon-btn:hover svg { transform: scale(1.2); }
          .asset-buttons { margin-top: 10px; }
        </style>
      </head>
      <body>
        <div class="order-container">
          <div class="order-header">
            <h1>Order #${orderId}</h1>
            <p>Your digital products are ready to download.</p>
          </div>
          ${productsHtml}
        </div>
      </body>
    </html>
  `);
});

// ---------- Shopify Order Webhook (Public) ----------
app.post('/webhook/order-created', async (req, res) => {
  const order = req.body;
  console.log('Received new order:', order.id);
  const shopifyDomain = new URL(order.order_status_url).hostname;
  console.log("Extracted shopify domain:", shopifyDomain);

  try {
    const tenantResult = await pool.query(
      "SELECT * FROM tenants WHERE shopify_store_url = $1",
      [shopifyDomain]
    );
    if (tenantResult.rows.length === 0) {
      console.error("Tenant not found for shop:", shopifyDomain);
      return res.sendStatus(500);
    }
    const tenant = tenantResult.rows[0];

    // --- NEW BLOCK: Check duplicate based on Big Order ID ---
    const existingOrder = await pool.query(
      "SELECT id FROM orders WHERE big_order_id = $1",
      [order.id]
    );
    if (existingOrder.rows.length > 0) {
      console.log("Duplicate order detected (big order id):", order.id);
      return res.sendStatus(200);
    }
    // --- End duplicate check ---

    await Promise.all(order.line_items.map(async (item) => {
      const productId = item.product_id;
      let fileUrl = null;
      try {
        const metafieldRes = await axios.get(`https://${shopifyDomain}/admin/api/2024-01/products/${productId}/metafields.json`, {
          headers: {
            'X-Shopify-Access-Token': tenant.shopify_api_password,
            'Content-Type': 'application/json'
          }
        });
        const metafields = metafieldRes.data.metafields;
        const digitalFileField = metafields.find(field => field.namespace === 'digital_download' && field.key === 'digital_file');
        if (digitalFileField) {
          fileUrl = digitalFileField.value;
          if (!fileUrl.includes('/')) {
            fileUrl = `${tenant.id}/${fileUrl}`;
          }
        }
      } catch (err) {
        console.error("Error fetching metafields for product", productId, err.response?.data || err.message);
      }
      if (fileUrl) {
        let assets;
        try {
          assets = JSON.parse(fileUrl);
          if (!Array.isArray(assets)) {
            assets = [fileUrl];
          }
        } catch (e) {
          assets = [fileUrl];
        }
        for (const asset of assets) {
          const token = generateDownloadToken(order.id, asset, tenant.id); // pass tenant.id too if needed
          if (!orderDeliveries[order.id]) orderDeliveries[order.id] = [];
          orderDeliveries[order.id].push({ productId, token });
          await pool.query(
            "INSERT INTO order_downloads (tenant_id, order_number, big_order_id, product_id, product_name, file_url, token) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            [tenant.id, order.order_number, order.id, productId, item.title, asset, token]
          );
        }
      }
      
      
    }));
    // --- Build download link using the short order number for display, but support lookup by both ---
    const downloadLink = `${process.env.APP_BASE_URL}/orders/${order.order_number}`;
    // Save order details (persist both big and short order ids)
    const customerName = order.customer ? `${order.customer.first_name} ${order.customer.last_name}`.trim() : "";
    const customerEmail = order.email || "";
    const shopifyCustomerUrl = order.customer && order.customer.id ? `https://${tenant.shopify_store_url}/admin/customers/${order.customer.id}` : "";
    const latestDispatchedEmail = new Date();
    await pool.query(
      "INSERT INTO orders (tenant_id, order_number, big_order_id, ordered_date, customer_name, customer_email, shopify_customer_url, latest_dispatched_email) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
      [tenant.id, order.order_number, order.id, order.created_at, customerName, customerEmail, shopifyCustomerUrl, latestDispatchedEmail]
    );
    const templateResult = await pool.query(
      "SELECT html FROM email_templates WHERE tenant_id = $1",
      [tenant.id]
    );
    let templateHtml;
    if (templateResult.rows.length === 0) {
      templateHtml = defaultEmailTemplate.html;
    } else {
      templateHtml = templateResult.rows[0].html;
    }
    // Replace the download_link placeholder with the actual link.
    const emailHtml = templateHtml.replace(/{{download_link}}/g, downloadLink);
    const today = new Date().toISOString().slice(0,10);
    await pool.query(
      "INSERT INTO stats (tenant_id, date, emails_sent, orders_served) VALUES ($1, $2, 1, 1) ON CONFLICT (tenant_id, date) DO UPDATE SET emails_sent = stats.emails_sent + 1, orders_served = stats.orders_served + 1",
      [tenant.id, today]
    );
    const smtpResult = await pool.query(
      "SELECT host, port, smtp_user as \"user\", pass FROM smtp_settings WHERE tenant_id = $1",
      [tenant.id]
    );
    await pool.query(
      "INSERT INTO activity_logs (tenant_id, event_type, message) VALUES ($1, $2, $3)",
      [tenant.id, 'Email Sent', `Download email sent for order: ${order.order_number} to ${order.email}`]
    );  
    
    const smtpRow = smtpResult.rows[0];
    let smtpConfig = {
      host: smtpRow ? smtpRow.host : process.env.SMTP_HOST,
      port: smtpRow ? parseInt(smtpRow.port) : parseInt(process.env.SMTP_PORT),
      secure: false,
      auth: {
        user: smtpRow ? smtpRow.user : process.env.SMTP_USER,
        pass: smtpRow ? smtpRow.pass : process.env.SMTP_PASS,
      },
      tls: { rejectUnauthorized: false },
      connectionTimeout: 10000  // 10 seconds, for example
    };
    let transporter = nodemailer.createTransport(smtpConfig);
    await transporter.sendMail({
      from: `"Your Shop" <${smtpConfig.auth.user}>`,
      to: order.email,
      subject: "Your Digital Download is Ready",
      text: `Thank you for your order. Access your digital downloads here: ${downloadLink}`,
      html: emailHtml
    });
    console.log('Email sent for order:', order.id);
    res.sendStatus(200);
  } catch (err) {
    console.error('Error processing order webhook:', err);
    res.sendStatus(500);
  }

});


// --- New Activity ----//
app.get('/admin/api/activity', ensureAuthenticated, async (req, res) => {
  const tenantId = req.session.tenant.id;
  try {
    const result = await pool.query(
      "SELECT event_type, message, created_at FROM activity_logs WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 10",
      [tenantId]
    );
    res.json({ activity: result.rows });
  } catch (err) {
    console.error("Error fetching activity logs:", err);
    res.status(500).json({ error: "DB error" });
  }
});


// New Route: Get Products with Digital Assets from the local Products table
app.get('/api/products-with-assets', ensureAuthenticated, async (req, res) => {
  const tenantId = req.session.tenant.id;
  try {
    const result = await pool.query(
      `SELECT id, shopify_product_id, title, image, digital_asset
       FROM products
       WHERE tenant_id = $1 AND digital_asset IS NOT NULL
       ORDER BY created_at DESC`,
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching products with digital assets:", err);
    res.status(500).json({ error: "DB error" });
  }
});


// New Route: Refresh Products with Digital Assets from Shopify and update local DB
app.get('/admin/api/refresh-products', ensureAuthenticated, async (req, res) => {
  try {
    const tenant = req.session.tenant;
    const shopDomain = tenant.shopify_store_url; // e.g., "your-store.myshopify.com"
    const apiVersion = '2023-07'; // Adjust if needed
    const accessToken = tenant.shopify_api_password; // Your admin API token

    // Helper function to fetch all products with pagination
    async function fetchAllProducts() {
      let products = [];
      let url = `https://${shopDomain}/admin/api/${apiVersion}/products.json?limit=250`;
      while (url) {
        const response = await fetch(url, {
          method: 'GET',
          headers: {
            'X-Shopify-Access-Token': accessToken,
            'Content-Type': 'application/json'
          }
        });
        const data = await response.json();
        products = products.concat(data.products);
        url = data.next_page_url || null;
      }
      return products;
    }

    // Helper function to fetch metafields for a given product
    async function fetchMetafieldsForProduct(productId) {
      const response = await fetch(`https://${shopDomain}/admin/api/${apiVersion}/products/${productId}/metafields.json`, {
        method: 'GET',
        headers: {
          'X-Shopify-Access-Token': accessToken,
          'Content-Type': 'application/json'
        }
      });
      return response.json();
    }

    // Fetch all products from Shopify
    const products = await fetchAllProducts();

    // For each product, fetch its metafields to check for a digital asset
    const upsertPromises = products.map(async (product) => {
      let digitalAsset = null;
      try {
        const metafieldsData = await fetchMetafieldsForProduct(product.id);
        const digitalDownloadMetafield = metafieldsData.metafields.find(
          m => m.namespace === "digital_download" && m.key === "digital_file"
        );
        if (digitalDownloadMetafield) {
          digitalAsset = digitalDownloadMetafield.value;
        }
      } catch (err) {
        console.error(`Error fetching metafields for product ${product.id}:`, err);
      }
      
      const imageUrl = product.image ? product.image.src : null;
      
      // Upsert into the local products table
      await pool.query(
        `INSERT INTO products (tenant_id, shopify_product_id, title, image, digital_asset)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (tenant_id, shopify_product_id)
         DO UPDATE SET title = EXCLUDED.title,
                       image = EXCLUDED.image,
                       digital_asset = EXCLUDED.digital_asset,
                       updated_at = NOW()`,
        [tenant.id, product.id, product.title, imageUrl, digitalAsset]
      );
    });
    await Promise.all(upsertPromises);
    res.json({ message: "Products refreshed successfully" });
  } catch (err) {
    console.error("Error refreshing products:", err);
    res.status(500).json({ error: "Error refreshing products" });
  }
});



// Delete assets
// New Route: Delete Digital Asset Metafield for a Product
app.delete('/api/delete-digital-asset', ensureAuthenticated, async (req, res) => {
  const { productId } = req.body;
  if (!productId) {
    return res.status(400).json({ error: "Missing productId" });
  }
  
  const tenant = req.session.tenant;
  const shopDomain = tenant.shopify_store_url;
  const apiVersion = '2023-07';  // Adjust if needed
  const accessToken = tenant.shopify_api_password;
  
  try {
    // 1. Fetch metafields for the product
    const metafieldsRes = await axios.get(`https://${shopDomain}/admin/api/${apiVersion}/products/${productId}/metafields.json`, {
      headers: {
        'X-Shopify-Access-Token': accessToken,
        'Content-Type': 'application/json'
      }
    });
    const metafields = metafieldsRes.data.metafields;
    const targetField = metafields.find(m => m.namespace === 'digital_download' && m.key === 'digital_file');
    
    if (!targetField) {
      return res.status(404).json({ error: 'Digital asset metafield not found' });
    }
    
    // 2. Delete the metafield via Shopify API
    await axios.delete(`https://${shopDomain}/admin/api/${apiVersion}/metafields/${targetField.id}.json`, {
      headers: {
        'X-Shopify-Access-Token': accessToken,
        'Content-Type': 'application/json'
      }
    });
    
    // 3. Optionally update your local products table to remove the digital asset (set to null)
    await pool.query(
      "UPDATE products SET digital_asset = NULL WHERE shopify_product_id = $1 AND tenant_id = $2",
      [productId, tenant.id]
    );
    
    res.json({ message: 'Digital asset metafield deleted successfully' });
  } catch (err) {
    console.error("Error deleting digital asset metafield:", err.response?.data || err.message);
    res.status(500).json({ error: 'Error deleting digital asset metafield' });
  }
});
// ----- Linked product assets ----//

app.get('/api/linked-products-count', ensureAuthenticated, async (req, res) => {
  const tenantId = req.session.tenant.id;
  try {
    const result = await pool.query(
      `SELECT digital_asset FROM products WHERE tenant_id = $1`,
      [tenantId]
    );

    const assetCounts = {};

    // Iterate through all products and count asset occurrences
    result.rows.forEach((row) => {
      if (row.digital_asset) {
        try {
          const assetList = JSON.parse(row.digital_asset);
          assetList.forEach((asset) => {
            assetCounts[asset] = (assetCounts[asset] || 0) + 1;
          });
        } catch (error) {
          console.error("Error parsing digital_asset:", error);
        }
      }
    });

    res.json({ assetCounts });
  } catch (err) {
    console.error("Error fetching linked product counts:", err);
    res.status(500).json({ error: "Error fetching linked product counts" });
  }
});

// ---------- Start the Server ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`App listening on port ${PORT}`));