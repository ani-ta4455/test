// server.js

// =======================================================
// --- IMPORTS & INITIALIZATION ---
// =======================================================

require('dotenv').config();
const express = require('express');
const bodyParser = 'body-parser';
const cors = require('cors');
const nodemailer = require('nodemailer');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const admin = require('firebase-admin');

// --- Firebase Admin SDK Initialization ---
try {
  // IMPORTANT: Ensure 'serviceAccountKey.json' is in your server's root directory
  // and added to your .gitignore file.
  const serviceAccount = require('./serviceAccountKey.json'); 
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log('Firebase Admin SDK initialized successfully.');
} catch (error) {
  console.error('FATAL: Firebase Admin SDK initialization failed. Make sure serviceAccountKey.json is present. Password reset will fail.', error.message);
}

const app = express();
const port = process.env.PORT || 5000;

// --- Nodemailer Transporter Setup ---
let transporter;
const smtpHost = process.env.SMTP_HOST;
const smtpPort = parseInt(process.env.SMTP_PORT, 10);
const smtpSecure = process.env.SMTP_SECURE === 'true';
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const emailFrom = process.env.EMAIL_FROM_ADDRESS || `"${smtpHost}" <${smtpUser}>`;

if (smtpHost && smtpPort && smtpUser && smtpPass) {
  const transporterOptions = {
    host: smtpHost,
    port: smtpPort,
    secure: smtpSecure,
    auth: {
      user: smtpUser,
      pass: smtpPass,
    },
  };
  transporter = nodemailer.createTransport(transporterOptions);
  transporter.verify(function (error, success) {
    if (error) {
      console.error('Nodemailer SMTP Configuration Error:', error);
    } else {
      console.log('Nodemailer SMTP server is ready to take our messages');
    }
  });
} else {
  console.error('FATAL: SMTP credentials (HOST, PORT, USER, PASS) are missing in .env. Email functionality will fail.');
}

// --- Razorpay Instance Setup ---
let razorpayInstance;
const razorpayKeyId = process.env.RAZORPAY_KEY_ID;
const razorpayKeySecret = process.env.RAZORPAY_KEY_SECRET;
const applicationFee = parseInt(process.env.APPLICATION_FEE, 10);

if (razorpayKeyId && razorpayKeySecret && !isNaN(applicationFee) && applicationFee > 0) {
  razorpayInstance = new Razorpay({
    key_id: razorpayKeyId,
    key_secret: razorpayKeySecret,
  });
  console.log('Razorpay instance initialized.');
} else {
  console.error('FATAL: Razorpay Key ID, Key Secret, or Application Fee missing/invalid in .env. Payment functionality will fail.');
}

// --- In-memory OTP & Token Storage ---
// Stores OTPs and single-use tokens for password resets and registrations.
const otpStore = {}; 

// --- Middleware ---
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
}));
app.use(express.json()); // Replaced bodyParser with express.json()
app.use(express.urlencoded({ extended: true })); // Replaced bodyParser with express.urlencoded()

// --- Helper Functions ---
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
function generateToken() { 
  return crypto.randomBytes(20).toString('hex'); 
}
const MAX_OTP_ATTEMPTS = 5;

// =======================================================
// --- AUTHENTICATION & VERIFICATION API ENDPOINTS ---
// =======================================================

// 1. Send Generic OTP Endpoint (For Registration & Password Reset)
app.post('/api/send-otp', async (req, res) => {
  const { email } = req.body;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email)) {
    return res.status(400).json({ message: 'Valid email address is required.' });
  }
  if (!transporter) {
    return res.status(500).json({ message: 'Email service configuration error.' });
  }

  const otp = generateOTP();
  const expiresAt = Date.now() + 10 * 60 * 1000; // OTP valid for 10 minutes
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
    console.error(`Error sending OTP to ${email}:`, error);
    res.status(500).json({ message: 'Failed to send verification code.' });
  }
});

// 2. Verify OTP Endpoint (Returns a single-use token on success)
app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ success: false, message: 'Email and OTP are required.' });
  }
  const lowerEmail = email.toLowerCase();
  const storedOtpData = otpStore[lowerEmail];

  if (!storedOtpData) {
    return res.status(400).json({ success: false, message: 'Verification code not found. Please request a new one.' });
  }
  if (Date.now() > storedOtpData.expiresAt) {
    delete otpStore[lowerEmail];
    return res.status(400).json({ success: false, message: 'Verification code has expired. Please request a new one.' });
  }
  if (storedOtpData.attempts >= MAX_OTP_ATTEMPTS) {
    delete otpStore[lowerEmail];
    return res.status(400).json({ success: false, message: 'Maximum attempts reached. Please request a new code.' });
  }
  
  if (storedOtpData.otp === otp) {
    const verificationToken = generateToken();
    const tokenExpiresAt = Date.now() + 5 * 60 * 1000; // Token valid for 5 minutes

    otpStore[lowerEmail].verificationToken = verificationToken;
    otpStore[lowerEmail].tokenExpiresAt = tokenExpiresAt;
    
    res.status(200).json({ 
      success: true, 
      message: 'OTP verified successfully.',
      verificationToken: verificationToken 
    });
  } else {
    otpStore[lowerEmail].attempts += 1;
    res.status(400).json({ success: false, message: 'Invalid verification code.' });
  }
});

// 3. Reset Password Endpoint (Requires a valid verification token)
app.post('/api/reset-password', async (req, res) => {
    const { email, newPassword, verificationToken } = req.body;
    if (!email || !newPassword || !verificationToken) {
        return res.status(400).json({ message: 'Email, new password, and verification token are required.' });
    }
    if (newPassword.length < 6) {
        return res.status(400).json({ message: 'Password must be at least 6 characters long.' });
    }

    const lowerEmail = email.toLowerCase();
    const storedData = otpStore[lowerEmail];

    if (!storedData || storedData.verificationToken !== verificationToken || Date.now() > storedData.tokenExpiresAt) {
        return res.status(401).json({ message: 'Invalid or expired verification token. Please start the process over.' });
    }
    
    try {
        const userRecord = await admin.auth().getUserByEmail(lowerEmail);
        await admin.auth().updateUser(userRecord.uid, { password: newPassword });
        delete otpStore[lowerEmail];
        res.status(200).json({ success: true, message: 'Password has been reset successfully. You can now log in.' });
    } catch (error) {
        console.error("Error during password reset:", error);
        if (error.code === 'auth/user-not-found') {
            return res.status(404).json({ message: 'No account is registered with this email address.' });
        }
        res.status(500).json({ message: 'An internal error occurred while resetting the password.' });
    }
});


// =======================================================
// --- PAYMENT PROCESSING API ENDPOINTS ---
// =======================================================

// 4. Create Razorpay Order Endpoint
app.post('/api/create-order', async (req, res) => {
  if (!razorpayInstance) {
    return res.status(500).json({ message: 'Payment gateway is not configured on the server.' });
  }
  const { currency = 'INR', receiptNotes = {} } = req.body;
  const compactTimestamp = Date.now().toString(36);
  let generatedReceipt = `rcpt_app_${compactTimestamp}`;
  const appId = receiptNotes.applicationId;
  if (appId && typeof appId === 'string') {
    const shortAppId = appId.substring(0, Math.min(appId.length, 10));
    generatedReceipt += `_${shortAppId}`;
  }
  generatedReceipt = generatedReceipt.substring(0, 40);
  const options = {
    amount: applicationFee,
    currency: currency,
    receipt: generatedReceipt,
    notes: receiptNotes
  };
  try {
    const order = await razorpayInstance.orders.create(options);
    if (!order) {
      return res.status(500).json({ message: 'Error creating Razorpay order.' });
    }
    res.json({ ...order, key_id: razorpayKeyId });
  } catch (error) {
    console.error('Razorpay order creation error:', error);
    const errorMessage = error.error && error.error.description ? error.error.description : "Could not create payment order.";
    res.status(error.statusCode || 500).json({ message: errorMessage, error: error.error });
  }
});

// 5. Verify Payment Signature Endpoint
app.post('/api/payment-verification', (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
  const secret = process.env.RAZORPAY_KEY_SECRET;
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({ success: false, message: 'Missing payment details for verification.' });
  }
  if (!secret) {
    console.error("FATAL: RAZORPAY_KEY_SECRET is not set. Cannot verify payment.");
    return res.status(500).json({ success: false, message: "Server payment configuration error." });
  }
  const shasum = crypto.createHmac('sha256', secret);
  shasum.update(`${razorpay_order_id}|${razorpay_payment_id}`);
  const digest = shasum.digest('hex');
  if (digest === razorpay_signature) {
    console.log('Payment verification successful for order:', razorpay_order_id);
    res.json({
      success: true,
      message: 'Payment verified successfully.',
      orderId: razorpay_order_id,
      paymentId: razorpay_payment_id
    });
  } else {
    console.warn('Payment verification failed for order:', razorpay_order_id);
    res.status(400).json({ success: false, message: 'Payment verification failed. Signature mismatch.' });
  }
});


// =======================================================
// --- SERVER HEALTH & STARTUP ---
// =======================================================

// --- Health Check ---
app.get('/health', (req, res) => {
  const adminStatus = admin.apps.length ? 'UP' : 'DOWN (Not initialized)';
  const nodemailerStatus = transporter ? 'UP' : 'DOWN (Not configured)';
  const razorpayStatus = razorpayInstance ? 'UP' : 'DOWN (Not configured)';
  res.status(200).json({ 
    status: 'UP', 
    message: 'Server is running.',
    services: {
        firebaseAdmin: adminStatus,
        nodemailer: nodemailerStatus,
        razorpay: razorpayStatus
    }
  });
});

// --- Start Server ---
app.listen(port, () => {
  console.log(`Backend server running on http://localhost:${port}`);
  if (!admin.apps.length) {
    console.error("CRITICAL: Firebase Admin SDK is NOT initialized. Password reset will fail.");
  }
  if (!transporter) {
    console.warn('WARNING: Nodemailer SMTP transporter not initialized. Email functionality will fail.');
  }
  if (!razorpayInstance) {
    console.warn('WARNING: Razorpay instance not initialized. Payment functionality will fail.');
  }
});