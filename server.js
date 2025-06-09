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

// =======================================================
// --- FIREBASE ADMIN SDK INITIALIZATION ---
// =======================================================
let serviceAccount;
try {
  if (process.env.SERVICE_ACCOUNT_PATH) {
    // Mounted secret file (Render Secret File)
    serviceAccount = require(process.env.SERVICE_ACCOUNT_PATH);
  } else if (process.env.FIREBASE_CREDENTIALS) {
    // Base64‐encoded JSON in env var
    serviceAccount = JSON.parse(
      Buffer.from(process.env.FIREBASE_CREDENTIALS, 'base64').toString('utf8')
    );
  } else {
    throw new Error('No Firebase credentials provided');
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
  console.log('✅ Firebase Admin SDK initialized successfully.');
} catch (error) {
  console.error(
    '❌ FATAL: Firebase Admin SDK initialization failed. ' +
      'Make sure SERVICE_ACCOUNT_PATH or FIREBASE_CREDENTIALS is set.',
    error.message
  );
  process.exit(1);
}

// =======================================================
// --- EXPRESS APP & PORT ---
// =======================================================
const app = express();
const port = process.env.PORT; // Render will inject this

// =======================================================
// --- NODemailer (SMTP) SETUP ---
// =======================================================
let transporter = null;
const smtpHost = process.env.SMTP_HOST;
const smtpPort = parseInt(process.env.SMTP_PORT, 10);
const smtpSecure = process.env.SMTP_SECURE === 'true';
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const emailFrom = process.env.EMAIL_FROM_ADDRESS || `"no-reply" <${smtpUser}>`;

if (smtpHost && smtpPort && smtpUser && smtpPass) {
  transporter = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: smtpSecure,
    auth: { user: smtpUser, pass: smtpPass },
  });

  transporter.verify((err, success) => {
    if (err) {
      console.error('❌ SMTP configuration error:', err.message);
    } else {
      console.log('✅ SMTP transporter ready.');
    }
  });
} else {
  console.warn(
    '⚠️  SMTP credentials missing. Email endpoints will return errors.'
  );
}

// =======================================================
// --- RAZORPAY SETUP ---
// =======================================================
const razorpayKeyId = process.env.RAZORPAY_KEY_ID;
const razorpayKeySecret = process.env.RAZORPAY_KEY_SECRET;
const applicationFee = parseInt(process.env.APPLICATION_FEE, 10);
let razorpayInstance = null;

if (razorpayKeyId && razorpayKeySecret && applicationFee > 0) {
  razorpayInstance = new Razorpay({
    key_id: razorpayKeyId,
    key_secret: razorpayKeySecret,
  });
  console.log('✅ Razorpay instance initialized.');
} else {
  console.warn(
    '⚠️  Razorpay credentials or APPLICATION_FEE missing/invalid. Payment endpoints will fail.'
  );
}

// =======================================================
// --- IN-MEMORY OTP STORE & HELPERS ---
// =======================================================
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
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type'],
  })
);
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
    return res.status(400).json({ message: 'Valid email address is required.' });
  }
  if (!transporter) {
    return res
      .status(500)
      .json({ message: 'Email service configuration error.' });
  }

  const otp = generateOTP();
  const expiresAt = Date.now() + 10 * 60 * 1000;
  otpStore[email.toLowerCase()] = { otp, expiresAt, attempts: 0 };

  const mailOptions = {
    from: emailFrom,
    to: email,
    subject: 'Your Verification Code for Ikon Education',
    html: `<p>Your One-Time Verification Code is: <b>${otp}</b>. It is valid for 10 minutes.</p>`,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: `Verification code sent to ${email}.` });
  } catch (error) {
    console.error(`❌ Error sending OTP to ${email}:`, error.message);
    res.status(500).json({ message: 'Failed to send verification code.' });
  }
});

// 2. Verify OTP
app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res
      .status(400)
      .json({ success: false, message: 'Email and OTP are required.' });
  }

  const stored = otpStore[email.toLowerCase()];
  if (!stored) {
    return res
      .status(400)
      .json({ success: false, message: 'No OTP found. Request a new one.' });
  }
  if (Date.now() > stored.expiresAt) {
    delete otpStore[email.toLowerCase()];
    return res
      .status(400)
      .json({ success: false, message: 'OTP expired. Request a new one.' });
  }
  if (stored.attempts >= MAX_OTP_ATTEMPTS) {
    delete otpStore[email.toLowerCase()];
    return res
      .status(400)
      .json({ success: false, message: 'Max attempts reached. Request again.' });
  }

  if (stored.otp === otp) {
    const token = generateToken();
    stored.verificationToken = token;
    stored.tokenExpiresAt = Date.now() + 5 * 60 * 1000;
    return res.status(200).json({
      success: true,
      message: 'OTP verified successfully.',
      verificationToken: token,
    });
  } else {
    stored.attempts += 1;
    return res
      .status(400)
      .json({ success: false, message: 'Invalid verification code.' });
  }
});

// 3. Reset Password
app.post('/api/reset-password', async (req, res) => {
  const { email, newPassword, verificationToken } = req.body;
  if (!email || !newPassword || !verificationToken) {
    return res.status(400).json({
      message: 'Email, new password, and verification token are required.',
    });
  }
  if (newPassword.length < 6) {
    return res
      .status(400)
      .json({ message: 'Password must be at least 6 characters.' });
  }

  const stored = otpStore[email.toLowerCase()];
  if (
    !stored ||
    stored.verificationToken !== verificationToken ||
    Date.now() > stored.tokenExpiresAt
  ) {
    return res
      .status(401)
      .json({ message: 'Invalid or expired verification token.' });
  }

  try {
    const user = await admin.auth().getUserByEmail(email.toLowerCase());
    await admin.auth().updateUser(user.uid, { password: newPassword });
    delete otpStore[email.toLowerCase()];
    return res
      .status(200)
      .json({ success: true, message: 'Password reset successfully.' });
  } catch (error) {
    console.error('❌ Error resetting password:', error.code || error.message);
    if (error.code === 'auth/user-not-found') {
      return res.status(404).json({
        message: 'No account found with that email address.',
      });
    }
    return res
      .status(500)
      .json({ message: 'Internal error during password reset.' });
  }
});

// =======================================================
// --- PAYMENT PROCESSING ENDPOINTS ---
// =======================================================

// 4. Create Razorpay Order
app.post('/api/create-order', async (req, res) => {
  if (!razorpayInstance) {
    return res
      .status(500)
      .json({ message: 'Payment gateway not configured.' });
  }

  const { currency = 'INR', receiptNotes = {} } = req.body;
  const timestamp = Date.now().toString(36);
  let receipt = `rcpt_app_${timestamp}`;
  if (receiptNotes.applicationId) {
    const shortId = receiptNotes.applicationId.toString().slice(0, 10);
    receipt += `_${shortId}`;
  }
  receipt = receipt.slice(0, 40);

  const options = {
    amount: applicationFee,
    currency,
    receipt,
    notes: receiptNotes,
  };

  try {
    const order = await razorpayInstance.orders.create(options);
    return res.json({ ...order, key_id: razorpayKeyId });
  } catch (error) {
    console.error('❌ Razorpay order error:', error.error || error.message);
    const msg =
      error.error?.description || 'Could not create payment order.';
    return res.status(error.statusCode || 500).json({ message: msg });
  }
});

// 5. Verify Payment Signature
app.post('/api/payment-verification', (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } =
    req.body;

  if (
    !razorpay_order_id ||
    !razorpay_payment_id ||
    !razorpay_signature
  ) {
    return res
      .status(400)
      .json({ success: false, message: 'Missing payment details.' });
  }

  if (!razorpayKeySecret) {
    console.error(
      '❌ FATAL: RAZORPAY_KEY_SECRET not set. Cannot verify payment.'
    );
    return res.status(500).json({
      success: false,
      message: 'Server payment configuration error.',
    });
  }

  const hmac = crypto.createHmac('sha256', razorpayKeySecret);
  hmac.update(`${razorpay_order_id}|${razorpay_payment_id}`);
  const digest = hmac.digest('hex');

  if (digest === razorpay_signature) {
    console.log('✅ Payment verified:', razorpay_order_id);
    return res.json({
      success: true,
      message: 'Payment verified successfully.',
      orderId: razorpay_order_id,
      paymentId: razorpay_payment_id,
    });
  } else {
    console.warn('⚠️  Payment signature mismatch:', razorpay_order_id);
    return res
      .status(400)
      .json({ success: false, message: 'Signature mismatch.' });
  }
});

// =======================================================
// --- HEALTH CHECK & STARTUP ---
// =======================================================

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

app.listen(port, () => {
  console.log(`🚀 Server running on port ${port}`);
  if (!admin.apps.length) {
    console.error(
      '🔴 CRITICAL: Firebase Admin not initialized. Password reset will fail.'
    );
  }
  if (!transporter) {
    console.warn(
      '🟠 WARNING: SMTP transporter not initialized. Email functionality will fail.'
    );
  }
  if (!razorpayInstance) {
    console.warn(
      '🟠 WARNING: Razorpay instance not initialized. Payment functionality will fail.'
    );
  }
});
