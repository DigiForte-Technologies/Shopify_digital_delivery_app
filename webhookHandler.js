const express = require("express");
const axios = require("axios");
const { Pool } = require("pg");
const crypto = require("crypto");

const app = express();
const PORT = 3000;

// PostgreSQL connection
const pool = new Pool({
  connectionString:
    "postgresql://neondb_owner:npg_vFbpeX5cSQC2@ep-frosty-math-a8ot8nq6-pooler.eastus2.azure.neon.tech/neondb?sslmode=require",
});

// Middleware to parse JSON
app.use(express.json());

// 🔹 Shopify Webhook Route
app.post("/webhook", async (req, res) => {
  try {
    // Extract webhook signature from headers
    const shopDomain = req.get("X-Shopify-Shop-Domain");
    const webhookSignature = req.get("X-Shopify-Hmac-SHA256");
    const accessToken1 = req.get("X-Shopify-Access-Token");

    if (!webhookSignature) {
      return res.status(401).send("Unauthorized: No webhook signature.");
    }

    // 🔹 Query PostgreSQL to get shop URL & webhook secret
    const { rows } = await pool.query(
      "SELECT shop_url, webhook_secret FROM webhook_signatures WHERE shop_url = $1",
      [shopDomain]
    );

    if (rows.length === 0) {
      return res.status(401).send("Unauthorized: Shop not found in DB.");
    }

    const { shop_url, webhook_secret } = rows[0];

    console.log("✅ Webhook verified!");

    // Extract order & customer ID
    const orderId = req.body.id;
    const customerId = req.body.customer?.id;

    if (!orderId || !customerId) {
      return res.status(400).send("Bad Request: Order or Customer ID missing.");
    }

    // 🔹 Fetch Full Order Details from Shopify API
    const shopifyOrderUrl = `https://${shop_url}/admin/api/2023-10/orders/${orderId}.json`;
    const orderResponse = await axios.get(shopifyOrderUrl, {
      headers: {
        "X-Shopify-Access-Token": accessToken1,
      },
    });

    const fullOrderData = orderResponse.data.order;

    // 🔹 Fetch Full Customer Details from Shopify API
    const shopifyCustomerUrl = `https://${shop_url}/admin/api/2023-10/customers/${customerId}.json`;
    const customerResponse = await axios.get(shopifyCustomerUrl, {
      headers: {
        "X-Shopify-Access-Token": accessToken1,
      },
    });

    const fullCustomerData = customerResponse.data.customer;

    // 🔹 Ensure `order_number` is always included
    let orderNumber = fullOrderData.order_number;
    if (!orderNumber) {
      console.warn("⚠️ Missing `order_number`, using `id` as fallback.");
      orderNumber = `#${orderId}`;
    }

    // 🔹 Transform Data into Required Format
    const formattedData = {
      id: fullOrderData.id,
      admin_graphql_api_id: fullOrderData.admin_graphql_api_id || "",
      app_id: fullOrderData.app_id || null,
      browser_ip: fullOrderData.browser_ip || "",
      buyer_accepts_marketing: fullOrderData.buyer_accepts_marketing || false,
      confirmation_number: fullOrderData.confirmation_number || "",
      contact_email: fullOrderData.contact_email || fullCustomerData.email || "",
      created_at: fullOrderData.created_at,
      currency: fullOrderData.currency,
      current_subtotal_price: fullOrderData.current_subtotal_price || "0.00",
      current_total_discounts: fullOrderData.current_total_discounts || "0.00",
      current_total_price: fullOrderData.current_total_price || "0.00",
      current_total_tax: fullOrderData.current_total_tax || "0.00",
      customer_locale: fullOrderData.customer_locale || "en",
      discount_codes: fullOrderData.discount_codes || [],
      email: fullCustomerData.email || "",
      financial_status: fullOrderData.financial_status || "",
      fulfillment_status: fullOrderData.fulfillment_status || "",
      name: fullOrderData.name || "",
      order_number: fullOrderData.order_number || orderNumber,
      order_status_url: "https://16255281.myshopify.com" || "",
      payment_gateway_names: fullOrderData.payment_gateway_names || [],
      presentment_currency: fullOrderData.presentment_currency || "CAD",
      processed_at: fullOrderData.processed_at,
      subtotal_price: fullOrderData.subtotal_price || "0.00",
      tags: fullOrderData.tags || "",
      tax_exempt: fullOrderData.tax_exempt || false,
      total_discounts: fullOrderData.total_discounts || "0.00",
      total_price: fullOrderData.total_price || "0.00",
      total_tax: fullOrderData.total_tax || "0.00",
      total_weight: fullOrderData.total_weight || 0,
      updated_at: fullOrderData.updated_at,
      billing_address: fullOrderData.billing_address || {},
      customer: {
        id: fullCustomerData.id || null,
        email: fullCustomerData.email || "",
        first_name: fullCustomerData.first_name || "",
        last_name: fullCustomerData.last_name || "",
        default_address: fullCustomerData.default_address || {},
      },
      line_items: fullOrderData.line_items.map((item) => ({
        id: item.id,
        variant_id: item.variant_id,
        product_id: item.product_id,
        name: item.name || "test",
        quantity: item.quantity,
        price: item.price,
        sku: item.sku,
        vendor: item.vendor,
        taxable: item.taxable,
      })),
      shipping_address: fullOrderData.shipping_address || {},
    };

    // 🔹 POST Data to `/webhook/order-created` Route
    const forwardUrl = "https://shopify-digital-download.fly.dev/webhook/order-created";
    await axios.post(forwardUrl, formattedData, {
      headers: {
        "Content-Type": "application/json",
      },
    });

    console.log("✅ Order Data Sent to:", forwardUrl);
    res.status(200).send("Webhook processed successfully.");
  } catch (error) {
    console.error("🚨 Error processing webhook:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Start the Express Server
app.listen(PORT, () => console.log(`🚀 Webhook server running on port ${PORT}`));
