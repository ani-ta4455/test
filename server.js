// server.js

// =======================================================
// --- IMPORTS & INITIALIZATION ---
// =======================================================
require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const admin = require('firebase-admin');

// =======================================================
// --- FIREBASE ADMIN SDK INITIALIZATION ---
// =======================================================
// This setup allows initialization from a file path (for local dev or Render Secret Files)
// or from a Base64-encoded environment variable (common for other hosting).
let serviceAccount;
try {
  if (process.env.SERVICE_ACCOUNT_PATH) {
    // Method 1: Path to a mounted secret file (e.g., Render Secret Files)
    serviceAccount = require(process.env.SERVICE_ACCOUNT_PATH);
  } else if (process.env.FIREBASE_CREDENTIALS) {
    // Method 2: Base64-encoded JSON string from an environment variable
    const decodedCredentials = Buffer.from(
      process.env.FIREBASE_CREDENTIALS,
      'base64'
    ).toString('utf8');
    serviceAccount = JSON.parse(decodedCredentials);
  } else {
    throw new Error('No Firebase credentials provided. Set SERVICE_ACCOUNT_PATH or FIREBASE_CREDENTIALS.');
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
  console.log('✅ Firebase Admin SDK initialized successfully.');
} catch (error) {
  console.error('❌ FATAL: Firebase Admin SDK initialization failed.', error.message);
  process.exit(1); // Exit if Firebase can't connect, as it's critical.
}

// =======================================================
// --- EXPRESS APP & PORT ---
// =======================================================
const app = express();
const port = process.env.PORT || 5000; // Render injects PORT; 5000 is a fallback for local dev

// =======================================================
// --- NODEMAILER (SMTP) SETUP ---
// =======================================================
let transporter = null;
const smtpHost = process.env.SMTP_HOST;
const smtpPort = parseInt(process.env.SMTP_PORT, 10);
const smtpSecure = process.env.SMTP_SECURE === 'true'; // Use 'true' for port 465, 'false' for 587
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const emailFrom = process.env.EMAIL_FROM_ADDRESS || `"Ikon Education" <${smtpUser}>`;

if (smtpHost && smtpPort && smtpUser && smtpPass) {
  transporter = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: smtpSecure,
    auth: { user: smtpUser, pass: smtpPass },
  });

  // Verify connection configuration on startup
  transporter.verify((err, success) => {
    if (err) {
      console.error('❌ SMTP configuration error:', err.message);
    } else {
      console.log('✅ SMTP transporter is ready to send emails.');
    }
  });
} else {
  console.warn('⚠️ SMTP credentials missing. Email endpoints will return errors.');
}

// =======================================================
// --- RAZORPAY SETUP ---
// =======================================================
let razorpayInstance = null;
const razorpayKeyId = process.env.RAZORPAY_KEY_ID;
const razorpayKeySecret = process.env.RAZORPAY_KEY_SECRET;
const applicationFee = parseInt(process.env.APPLICATION_FEE, 10) || 0;

if (razorpayKeyId && razorpayKeySecret && applicationFee > 0) {
  razorpayInstance = new Razorpay({
    key_id: razorpayKeyId,
    key_secret: razorpayKeySecret,
  });
  console.log('✅ Razorpay instance initialized.');
} else {
  console.warn('⚠️ Razorpay credentials or a valid APPLICATION_FEE missing. Payment endpoints will fail.');
}

// =======================================================
// --- IN-MEMORY OTP STORE & HELPERS ---
// =======================================================
// WARNING: This in-memory store is NOT suitable for a production environment
// that may have multiple server instances or restarts (like Render).
// It will lose all OTP data on every deploy/restart.
// For production, use a persistent store like Redis, Memcached, or a Firestore collection.
const otpStore = {};
const MAX_OTP_ATTEMPTS = 5;

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateToken() {
  return crypto.randomBytes(20).toString('hex');
}

// =======================================================
// --- MIDDLEWARE ---
// =======================================================
// Configure CORS to allow requests ONLY from your frontend URL
const corsOptions = {
  origin: process.env.FRONTEND_URL,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
};
app.use(cors(corsOptions));

// Body parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// =======================================================
// --- AUTH & VERIFICATION ENDPOINTS ---
// =======================================================

// 1. Send OTP
app.post('/api/send-otp', async (req, res) => {
  const { email } = req.body;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email)) {
    return res.status(400).json({ message: 'A valid email address is required.' });
  }
  if (!transporter) {
    return res.status(503).json({ message: 'Email service is not configured on the server.' });
  }

  const normalizedEmail = email.toLowerCase();
  const otp = generateOTP();
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
  otpStore[normalizedEmail] = { otp, expiresAt, attempts: 0 };

  const mailOptions = {
    from: emailFrom,
    to: normalizedEmail,
    subject: 'Your Verification Code for Ikon Education',
    html: `<p>Your One-Time Verification Code is: <b>${otp}</b>. It is valid for 10 minutes.</p>`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`OTP sent to ${normalizedEmail}`);
    res.status(200).json({ message: `Verification code sent to ${email}.` });
  } catch (error) {
    console.error(`❌ Error sending OTP to ${normalizedEmail}:`, error.message);
    res.status(500).json({ message: 'Failed to send verification code. Please try again later.' });
  }
});

// 2. Verify OTP
app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ success: false, message: 'Email and OTP are required.' });
  }

  const normalizedEmail = email.toLowerCase();
  const stored = otpStore[normalizedEmail];

  if (!stored) {
    return res.status(400).json({ success: false, message: 'OTP not found or expired. Please request a new one.' });
  }
  if (Date.now() > stored.expiresAt) {
    delete otpStore[normalizedEmail];
    return res.status(400).json({ success: false, message: 'OTP has expired. Please request a new one.' });
  }
  if (stored.attempts >= MAX_OTP_ATTEMPTS) {
    delete otpStore[normalizedEmail];
    return res.status(429).json({ success: false, message: 'Too many incorrect attempts. Please request a new OTP.' });
  }

  if (stored.otp === otp) {
    const token = generateToken();
    stored.verificationToken = token;
    // Token for password reset is valid for a shorter time after OTP verification
    stored.tokenExpiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
    return res.status(200).json({
      success: true,
      message: 'OTP verified successfully.',
      verificationToken: token,
    });
  } else {
    stored.attempts += 1;
    return res.status(400).json({ success: false, message: 'Invalid verification code.' });
  }
});

// 3. Reset Password
app.post('/api/reset-password', async (req, res) => {
  const { email, newPassword, verificationToken } = req.body;
  if (!email || !newPassword || !verificationToken) {
    return res.status(400).json({ message: 'Email, new password, and verification token are all required.' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters long.' });
  }

  const normalizedEmail = email.toLowerCase();
  const stored = otpStore[normalizedEmail];
  if (!stored || stored.verificationToken !== verificationToken || Date.now() > stored.tokenExpiresAt) {
    return res.status(401).json({ message: 'Invalid or expired verification token. Please start the process again.' });
  }

  try {
    const user = await admin.auth().getUserByEmail(normalizedEmail);
    await admin.auth().updateUser(user.uid, { password: newPassword });
    delete otpStore[normalizedEmail]; // Clean up the store
    console.log(`Password reset for user: ${normalizedEmail}`);
    return res.status(200).json({ success: true, message: 'Password has been reset successfully.' });
  } catch (error) {
    console.error('❌ Error resetting password:', error.code || error.message);
    if (error.code === 'auth/user-not-found') {
      return res.status(404).json({ message: 'No account found with that email address.' });
    }
    return res.status(500).json({ message: 'An internal error occurred during password reset.' });
  }
});


// =======================================================
// --- PAYMENT PROCESSING ENDPOINTS ---
// =======================================================

// 4. Create Razorpay Order
app.post('/api/create-order', async (req, res) => {
  if (!razorpayInstance) {
    return res.status(503).json({ message: 'Payment gateway is not configured on the server.' });
  }

  // notes can be used to pass extra info, like applicationId, which is useful for reconciliation
  const { currency = 'INR', notes = {} } = req.body;
  const timestamp = Date.now();
  // Create a unique receipt ID, ensuring it's within Razorpay's 40-char limit
  let receipt = `rcpt_ikon_${timestamp}`;
  if (notes.applicationId) {
    receipt += `_${notes.applicationId.slice(0, 10)}`;
  }
  receipt = receipt.slice(0, 40);

  const options = {
    amount: applicationFee, // amount in the smallest currency unit (e.g., paisa for INR)
    currency,
    receipt,
    notes,
  };

  try {
    const order = await razorpayInstance.orders.create(options);
    // Return the key_id along with the order details
    return res.status(200).json({ ...order, key_id: razorpayKeyId });
  } catch (error) {
    console.error('❌ Razorpay order creation error:', error.error || error);
    const msg = error.error?.description || 'Could not create payment order.';
    return res.status(error.statusCode || 500).json({ message: msg });
  }
});

// 5. Verify Payment Signature
app.post('/api/payment-verification', (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({ success: false, message: 'Missing required payment details.' });
  }
  if (!razorpayKeySecret) {
    console.error('❌ FATAL: RAZORPAY_KEY_SECRET not set. Cannot verify payment signature.');
    return res.status(500).json({ success: false, message: 'Server payment configuration error.' });
  }

  const body = `${razorpay_order_id}|${razorpay_payment_id}`;
  const expectedSignature = crypto
    .createHmac('sha256', razorpayKeySecret)
    .update(body)
    .digest('hex');

  if (expectedSignature === razorpay_signature) {
    console.log(`✅ Payment verified successfully for order: ${razorpay_order_id}`);
    // Here, you would typically update your database to mark the order as paid.
    return res.status(200).json({
      success: true,
      message: 'Payment verified successfully.',
      orderId: razorpay_order_id,
      paymentId: razorpay_payment_id,
    });
  } else {
    console.warn(`⚠️ Payment signature mismatch for order: ${razorpay_order_id}`);
    return res.status(400).json({ success: false, message: 'Payment signature validation failed.' });
  }
});


// =======================================================
// --- HEALTH CHECK & STARTUP ---
// =======================================================

// A simple endpoint to check if the server and its services are running.
app.get('/health', (req, res) => {
  const isFirebaseUp = admin.apps.length > 0;
  const isSmtpUp = !!transporter;
  const isRazorpayUp = !!razorpayInstance;
  
  const status = isFirebaseUp && isSmtpUp && isRazorpayUp ? 200 : 503;

  res.status(status).json({
    status: status === 200 ? 'UP' : 'DEGRADED',
    timestamp: new Date().toISOString(),
    services: {
      firebase: isFirebaseUp ? 'UP' : 'DOWN',
      smtp: isSmtpUp ? 'UP' : 'DOWN',
      razorpay: isRazorpayUp ? 'UP' : 'DOWN',
    },
  });
});

app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
  console.log(`Frontend URL allowed via CORS: ${process.env.FRONTEND_URL}`);
  if (!process.env.FRONTEND_URL) {
    console.error('🔴 CRITICAL: FRONTEND_URL is not set. All API requests will be blocked by CORS.');
  }
});
