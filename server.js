// server.js
// =======================================================
// --- IMPORTS & INITIALIZATION ---
// =======================================================
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const admin = require('firebase-admin');

// --- Firebase Admin SDK Initialization ---
let serviceAccount;
if (process.env.SERVICE_ACCOUNT_PATH) {
  // Mounted secret file (Render “Secret File” / Docker volume)
  serviceAccount = require(process.env.SERVICE_ACCOUNT_PATH);
} else if (process.env.FIREBASE_CREDENTIALS) {
  // Base64‐encoded JSON in env var
  serviceAccount = JSON.parse(
    Buffer.from(process.env.FIREBASE_CREDENTIALS, 'base64').toString('utf8')
  );
} else {
  console.error(
    'FATAL: No Firebase credentials found. Set SERVICE_ACCOUNT_PATH or FIREBASE_CREDENTIALS.'
  );
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
console.log('✅ Firebase Admin SDK initialized.');

// --- Express Setup ---
const app = express();
const port = process.env.PORT || 5000;

// --- Nodemailer Setup ---
let transporter = null;
if (
  process.env.SMTP_HOST &&
  process.env.SMTP_PORT &&
  process.env.SMTP_USER &&
  process.env.SMTP_PASS
) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT, 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
  transporter.verify((err) => {
    if (err) console.error('❌ SMTP config error:', err);
    else console.log('✅ SMTP ready.');
  });
} else {
  console.warn('⚠️  SMTP not configured; email endpoints will fail.');
}

// --- Razorpay Setup ---
let razorpayInstance = null;
if (process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET) {
  razorpayInstance = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
  });
  console.log('✅ Razorpay initialized.');
} else {
  console.warn('⚠️  Razorpay not configured; payment endpoints will fail.');
}

// --- In‐Memory Stores & Middleware ---
const otpStore = {};
const MAX_OTP_ATTEMPTS = 5;

app.use(
  cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type'],
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- Helpers ---
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
function generateToken() {
  return crypto.randomBytes(20).toString('hex');
}

// =======================================================
// --- ROUTES (send-otp, verify-otp, reset-password, create-order, payment-verification, health) ---
// (Copy exactly from your existing code; omitted here for brevity.)
// =======================================================

// Example: Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'UP',
    services: {
      firebase: admin.apps.length ? 'UP' : 'DOWN',
      smtp: transporter ? 'UP' : 'DOWN',
      razorpay: razorpayInstance ? 'UP' : 'DOWN',
    },
  });
});

// Start
app.listen(port, () => {
  console.log(`🚀 Server listening on port ${port}`);
});
