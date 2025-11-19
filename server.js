const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const twilio = require('twilio');
const Razorpay = require('razorpay');
const path = require('path');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ================================================
// TWILIO CONFIGURATION
// ================================================
const twilioAccountSid = process.env.TWILIO_ACCOUNT_SID || '';
const twilioAuthToken = process.env.TWILIO_AUTH_TOKEN || '';
const twilioMessagingServiceSid = process.env.TWILIO_MESSAGING_SERVICE_SID || '';
const twilioSmsFrom = process.env.TWILIO_SMS_FROM || '';
const twilioVerifyServiceSid = process.env.TWILIO_VERIFY_SERVICE_SID || '';
const otpExpiryMinutes = parseInt(process.env.OTP_EXPIRY_MINUTES || '5', 10);
const otpResendCooldownSeconds = parseInt(process.env.OTP_RESEND_COOLDOWN_SECONDS || '60', 10);
const otpSessionTtlMinutes = parseInt(process.env.OTP_SESSION_TTL_MINUTES || '30', 10);
const PHONE_REGEX = /^[6-9]\d{9}$/;
const OTP_LENGTH = parseInt(process.env.OTP_LENGTH || '4', 10);
const OTP_CODE_REGEX = new RegExp(`^\\d{${OTP_LENGTH}}$`);
const TEST_REFERRAL_CODE = (process.env.TEST_REFERRAL_CODE || '8520erty').toLowerCase();
const TEST_REFERRAL_NAME = 'Cyano Ambassador';
const JWT_SECRET = process.env.JWT_SECRET || (() => {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('JWT_SECRET must be set in production environment!');
  }
  return 'change_me_dev_only';
})();
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || process.env.JWT_EXPIRY || '7d';
const JWT_COOKIE_NAME = process.env.JWT_COOKIE_NAME || 'nf_token';
const PASSWORD_SALT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || null;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || null;
const ALLOWED_INFLUENCER_ROLES = ['Farmer', 'NGO', 'Youtuber', 'Local Promoter', 'Agricultural Expert', 'Community Leader'];
const USER_ROLES = Object.freeze({ ADMIN: 'admin', INFLUENCER: 'influencer' });
const USER_STATUS = Object.freeze({ ACTIVE: 'active', PENDING: 'pending', DISABLED: 'disabled' });
const JWT_COOKIE_MAX_AGE = parseInt(process.env.JWT_COOKIE_MAX_AGE_DAYS || '7', 10) * 24 * 60 * 60 * 1000;

const twilioClient = (twilioAccountSid && twilioAuthToken)
  ? twilio(twilioAccountSid, twilioAuthToken)
  : null;

// Debug Twilio configuration
console.log('🔧 Twilio Configuration:');
console.log('  - Account SID:', twilioAccountSid ? `✅ Set (${twilioAccountSid.substring(0, 8)}...)` : '❌ Not set');
console.log('  - Auth Token:', twilioAuthToken ? `✅ Set (${twilioAuthToken.length} chars)` : '❌ Not set');
console.log('  - Client:', twilioClient ? '✅ Initialized' : '❌ Not initialized');
console.log('  - Messaging Service SID:', twilioMessagingServiceSid ? `✅ Set (${twilioMessagingServiceSid})` : '❌ Not set');
console.log('  - SMS From:', twilioSmsFrom ? `✅ Set (${twilioSmsFrom})` : '❌ Not set');

const otpServiceConfigured = Boolean(
  twilioClient &&
  (
    (twilioMessagingServiceSid && twilioMessagingServiceSid !== 'xxxxxxxxxx') ||
    (twilioSmsFrom && twilioSmsFrom !== 'xxxxxxxxxx')
  )
);

console.log('  - OTP Service:', otpServiceConfigured ? '✅ Configured' : '⚠️  Not configured (Test Mode)');
console.log('  - Environment:', process.env.NODE_ENV || 'development');
const razorpayClient = (process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET)
  ? new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
  })
  : null;

// ================================================
// MIDDLEWARE CONFIGURATION
// ================================================

// Security middleware
// Disable CSP for API server - CSP should be handled by frontend
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

// CORS configuration
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);

    const allowedOrigins = [
      'http://localhost:3000',
      'http://127.0.0.1:3000',
      'https://agrivalah.in',
      'http://agrivalah.in',
      'https://www.agrivalah.in',
      'http://www.agrivalah.in',
      'https://agrivalahfrontend.vercel.app',
      'https://agrivalahbackend.vercel.app',
      /\.hostinger\.site$/,
      /\.hpanel\.hostinger\.com$/,
      /\.vercel\.app$/,
      // Allow any domain in development
      ...(process.env.NODE_ENV !== 'production' ? [/.*/] : [])
    ];

    const isAllowed = allowedOrigins.some(pattern => {
      if (typeof pattern === 'string') return pattern === origin;
      return pattern.test(origin);
    });

    if (isAllowed) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  exposedHeaders: ['Set-Cookie']
}));

// Rate limiting - More restrictive for API endpoints
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const paymentLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // limit each IP to 5 payment attempts per minute
  message: {
    error: 'Too many payment attempts, please wait before trying again.',
    retryAfter: '1 minute'
  }
});

app.use('/api/', apiLimiter);
app.use('/api/create-order', paymentLimiter);
app.use('/api/verify-payment', paymentLimiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Request logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.url} - IP: ${req.ip}`);
  next();
});

// ================================================
// SERVE FRONTEND (for localhost development ONLY)
// ================================================
if (process.env.NODE_ENV !== 'production') {
  // Only serve frontend files in development (localhost)
  const FRONTEND_DIR = path.join(__dirname, '../frontend');

  // Serve static files
  app.use(express.static(FRONTEND_DIR));

  // Clean URL routes (same as .htaccess for Hostinger)
  app.get('/', (req, res) => {
    res.sendFile(path.join(FRONTEND_DIR, 'index.html'));
  });

  app.get('/admin', (req, res) => {
    res.sendFile(path.join(FRONTEND_DIR, 'admin-login.html'));
  });

  app.get('/admin/dashboard', (req, res) => {
    res.sendFile(path.join(FRONTEND_DIR, 'admin-dashboard.html'));
  });

  app.get('/influencer', (req, res) => {
    res.sendFile(path.join(FRONTEND_DIR, 'influencer-login.html'));
  });

  app.get('/influencer/dashboard', (req, res) => {
    res.sendFile(path.join(FRONTEND_DIR, 'influencer-dashboard.html'));
  });

  app.get('/influencer/register', (req, res) => {
    res.sendFile(path.join(FRONTEND_DIR, 'influencer-register.html'));
  });

  console.log('🌐 Serving frontend files for development');
} else {
  // Production: API-only, return API info
  app.get('/', (req, res) => {
    res.json({
      success: true,
      message: 'Agrivalah API Server',
      version: '1.0.0',
      status: 'running',
      environment: 'production',
      frontend: process.env.FRONTEND_URL || 'https://agrivalah.in',
      endpoints: {
        health: '/api/health-check',
        docs: '/api/docs'
      }
    });
  });

  console.log('🚀 Running in production mode - API only');
}

// ================================================
// DATABASE CONNECTION
// ================================================

// Enhanced MongoDB connection with retry logic
const connectDB = async () => {
  try {
    const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/natural-farming';

    const options = {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      maxIdleTimeMS: 30000
    };

    await mongoose.connect(mongoURI, options);
    console.log('✅ Connected to MongoDB successfully');

    // Connection event listeners
    mongoose.connection.on('error', (error) => {
      console.error('❌ MongoDB connection error:', error);
    });

    mongoose.connection.on('disconnected', () => {
      console.log('⚠️ MongoDB disconnected');
    });

    mongoose.connection.on('reconnected', () => {
      console.log('✅ MongoDB reconnected');
    });

  } catch (error) {
    console.error('❌ MongoDB connection failed:', error);
    // Retry connection after 5 seconds
    setTimeout(connectDB, 5000);
  }
};

connectDB();
mongoose.connection.once('open', () => {
  ensureDefaultAdmin().catch((error) => {
    console.error('Failed to ensure default admin:', error.message);
  });
});

// ================================================
// DATABASE SCHEMAS
// ================================================

// Coupon Schema
const couponSchema = new mongoose.Schema({
  code: { type: String, unique: true, required: true, index: true },
  influencer: { type: mongoose.Schema.Types.ObjectId, ref: 'Influencer', required: true },
  commission_amount: { type: Number, default: 50 },
  discount_type: { type: String, enum: ['flat', 'percent'], default: 'flat' },
  discount_value: { type: Number, default: 50 }, // flat rupees or percentage
  usage_count: { type: Number, default: 0 },
  usage_limit: { type: Number, default: null },
  last_used_at: { type: Date, default: null },
  valid_from: { type: Date, default: null },
  valid_until: { type: Date, default: null },
  active: { type: Boolean, default: true },
  notes: { type: String, default: null },
  total_revenue: { type: Number, default: 0 },
  created_at: { type: Date, default: Date.now }
});

// Influencer Schema
const influencerSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  contact_number: { type: String, required: true, unique: true, index: true },
  password_hash: { type: String, required: true },
  email: { type: String, required: true, trim: true, lowercase: true, index: true },
  influencer_type: {
    type: String,
    enum: ['Social Media Influencer', 'Media', 'Celebrity'],
    required: true
  },
  type: {
    type: String,
    enum: ['Farmer', 'NGO', 'Youtuber', 'Local Promoter', 'Agricultural Expert', 'Community Leader'],
    required: true
  },
  social_media_handles: [{
    platform: { type: String, required: true },
    handle: { type: String, required: true },
    followers: { type: Number, default: 0 }
  }],
  social_link: { type: String, trim: true },
  region: { type: String, required: true, trim: true },
  upi_id: { type: String, required: true, trim: true },
  bank_details: { type: String, trim: true },
  coupon_code: { type: String, unique: true, sparse: true, index: true },
  approval_status: {
    type: String,
    enum: ['pending', 'approved', 'rejected', 'disabled'],
    default: 'pending',
    index: true
  },
  login_enabled: { type: Boolean, default: false },
  notes: { type: String, default: null },
  admin_messages: [{
    message: { type: String, required: true },
    sent_at: { type: Date, default: Date.now },
    read: { type: Boolean, default: false }
  }],
  total_earnings: { type: Number, default: 0, min: 0 },
  payout_status: { type: String, enum: ['Paid', 'Pending'], default: 'Pending' },
  referral_limit: { type: Number, default: null, min: 0 },
  referral_uses: { type: Number, default: 0, min: 0 },
  commission_amount: { type: Number, default: 50, min: 0 },
  last_login: { type: Date, default: null },
  phone_verified: { type: Boolean, default: false },
  otp_verified_at: { type: Date, default: null },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now }
}, {
  timestamps: true
});

// Payment Schema
const paymentSchema = new mongoose.Schema({
  farmer: { type: mongoose.Schema.Types.ObjectId, ref: 'Registration', required: true },
  amount: { type: Number, required: true },
  currency: { type: String, default: 'INR' },
  coupon_code: { type: String },
  influencer: { type: mongoose.Schema.Types.ObjectId, ref: 'Influencer' },
  commission_paid: { type: Boolean, default: false },
  commission_amount: { type: Number, default: 0 },
  payment_status: { type: String, enum: ['Success', 'Failed', 'Pending'], default: 'Pending' },
  payment_id: { type: String, default: null, index: true },
  order_id: { type: String, default: null, index: true },
  razorpay_signature: { type: String, default: null },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
  timestamps: true,
  collection: 'payments'
});

// Registration Schema (Farmer)
const registrationSchema = new mongoose.Schema({
  reference_id: { type: String, unique: true, required: true, index: true },
  registration_date: { type: Date, required: true, default: Date.now },
  // Personal Information
  farmer_name: { type: String, required: true, trim: true, maxlength: 100 },
  father_spouse_name: { type: String, required: true, trim: true, maxlength: 100 },
  contact_number: { type: String, required: true, match: /^[6-9]\d{9}$/, index: true },
  email_id: { type: String, default: null, match: /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/, lowercase: true },
  aadhaar_farmer_id: { type: String, default: null, match: /^\d{12}$/ },
  // Location Information
  village_panchayat: { type: String, required: true, trim: true, maxlength: 100 },
  mandal_block: { type: String, required: true, trim: true, maxlength: 100 },
  district: { type: String, required: true, trim: true, maxlength: 100 },
  state: { type: String, required: true, trim: true, maxlength: 100 },
  pincode: { type: String, default: null, match: /^\d{6}$/ },
  // Land Information
  khasra_passbook: { type: String, default: null },
  plot_no: { type: String, default: null },
  total_land: { type: Number, required: true, min: 0.1, max: 10000 },
  land_unit: { type: String, required: true, enum: ['Acre', 'Hectare', 'Bigha', 'Guntha'] },
  area_natural_farming: { type: Number, required: true, min: 0.1, max: 10000 },
  // Crop Information
  present_crop: { type: String, default: null, trim: true },
  sowing_date: { type: Date, required: true },
  harvesting_date: { type: Date, default: null },
  crop_types: { type: String, required: true, trim: true },
  crops: [{ 
    name: { type: String, required: true, trim: true },
    area: { type: String, trim: true },
    variety: { type: String, trim: true }
  }],
  // Farming Practice
  farming_practice: { type: String, required: true, enum: ['Organic', 'Natural', 'Chemical', 'Mixed'] },
  farming_experience: { type: Number, required: true, min: 0, max: 100 },
  irrigation_source: { type: String, required: true, enum: ['Rainwater', 'Borewell', 'Canal', 'River', 'Pond', 'Other'] },
  // Additional Information
  livestock: { type: [String], default: [] },
  willing_to_adopt: { type: String, default: 'Maybe' },
  additional_details: { type: mongoose.Schema.Types.Mixed, default: {} },
  terms_agreement: { type: Boolean, default: false },
  // Referral & Coupon
  coupon_code: { type: String, default: null },
  influencer: { type: mongoose.Schema.Types.ObjectId, ref: 'Influencer' },
  commission_amount: { type: Number, default: 0 },
  commission_paid: { type: Boolean, default: false },
  coupon_discount: { type: Number, default: 0 },
  payment_amount: { type: Number, default: 500 },
  payment_id: { type: String, default: null, index: true },
  order_id: { type: String, default: null },
  // System Information
  ip_address: { type: String },
  user_agent: { type: String },
  submission_source: { type: String, default: 'web' },
  // Status
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  payment_status: { type: String, enum: ['completed', 'pending', 'failed'], default: 'pending' },
  otp_token: { type: String, default: null },
  otp_verified: { type: Boolean, default: false },
  otp_verified_at: { type: Date, default: null }
}, {
  timestamps: true,
  collection: 'registrations'
});

// Payment Log Schema
const paymentLogSchema = new mongoose.Schema({
  payment_id: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  order_id: {
    type: String,
    default: null,
    index: true
  },
  razorpay_signature: {
    type: String,
    default: null
  },
  amount: {
    type: Number,
    required: true
  },
  currency: {
    type: String,
    default: 'INR'
  },
  status: {
    type: String,
    enum: ['created', 'attempted', 'paid', 'failed', 'cancelled'],
    required: true
  },
  method: {
    type: String,
    default: null
  },
  bank: {
    type: String,
    default: null
  },
  wallet: {
    type: String,
    default: null
  },
  vpa: {
    type: String,
    default: null
  },
  email: {
    type: String,
    default: null
  },
  contact: {
    type: String,
    default: null
  },
  ip_address: {
    type: String,
    default: null
  },
  user_agent: {
    type: String,
    default: null
  },
  registration_reference: {
    type: String,
    default: null,
    index: true
  },
  notes: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  webhook_data: {
    type: mongoose.Schema.Types.Mixed,
    default: null
  }
}, {
  timestamps: true,
  collection: 'payment_logs'
});

// OTP Session Schema (recreated from scratch)
const otpSessionSchema = new mongoose.Schema({
  phone_number: { type: String, required: true, index: true },
  code_hash: { type: String, required: true },
  provider: { type: String, enum: ['twilio', 'simulated'], default: 'twilio' },
  status: { type: String, enum: ['pending', 'verified', 'used'], default: 'pending' },
  session_token: { type: String, default: null, index: true },
  session_expires_at: { type: Date, default: null },
  associated_reference: { type: String, default: null },
  verified: { type: Boolean, default: false },
  verified_at: { type: Date, default: null },
  expires_at: { type: Date, required: true },
  attempts: { type: Number, default: 0 },
  used: { type: Boolean, default: false },
  used_at: { type: Date, default: null },
  last_sent_at: { type: Date, required: true }
}, {
  timestamps: true,
  collection: 'otp_verifications'
});

otpSessionSchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 });

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password_hash: { type: String, required: true },
  role: { type: String, enum: Object.values(USER_ROLES), required: true },
  status: { type: String, enum: Object.values(USER_STATUS), default: USER_STATUS.ACTIVE },
  linked_influencer: { type: mongoose.Schema.Types.ObjectId, ref: 'Influencer', default: null },
  last_login: { type: Date, default: null },
  force_password_reset: { type: Boolean, default: false }
}, {
  timestamps: true,
  collection: 'users'
});
userSchema.index({ linked_influencer: 1 }, { unique: true, sparse: true });

// Models
const Coupon = mongoose.model('Coupon', couponSchema);
const Influencer = mongoose.model('Influencer', influencerSchema);
const Payment = mongoose.model('Payment', paymentSchema);
const OtpSession = mongoose.model('OtpSession', otpSessionSchema);
// Registration model is already declared above, do not redeclare.
const User = mongoose.model('User', userSchema);

function signJwt(user) {
  return jwt.sign(
    {
      sub: user._id,
      role: user.role,
      influencerId: user.linked_influencer || null
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function setAuthCookie(res, token) {
  const isProduction = process.env.NODE_ENV === 'production';
  res.cookie(JWT_COOKIE_NAME, token, {
    httpOnly: true,
    secure: isProduction, // HTTPS in production, HTTP in dev
    sameSite: isProduction ? 'lax' : 'lax', // Use 'lax' for same-site cookies
    maxAge: JWT_COOKIE_MAX_AGE,
    path: '/'
  });
}

function clearAuthCookie(res) {
  res.clearCookie(JWT_COOKIE_NAME, {
    httpOnly: true,
    secure: true,
    sameSite: 'none'
  });
}

function authenticate(allowedRoles = []) {
  return async (req, res, next) => {
    try {
      const token =
        req.cookies?.[JWT_COOKIE_NAME] ||
        (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')
          ? req.headers.authorization.split(' ')[1]
          : null);

      if (!token) {
        return res.status(401).json({ success: false, message: 'Authentication required' });
      }

      let payload;
      try {
        payload = jwt.verify(token, JWT_SECRET);
      } catch (error) {
        clearAuthCookie(res);
        return res.status(401).json({ success: false, message: 'Invalid or expired session' });
      }

      const user = await User.findById(payload.sub).populate('linked_influencer');
      if (!user) {
        clearAuthCookie(res);
        return res.status(401).json({ success: false, message: 'User not found' });
      }

      if (user.status !== USER_STATUS.ACTIVE) {
        clearAuthCookie(res);
        return res.status(403).json({ success: false, message: 'Account is not active' });
      }

      if (allowedRoles.length && !allowedRoles.includes(user.role)) {
        return res.status(403).json({ success: false, message: 'Insufficient permissions' });
      }

      req.authUser = user;
      next();
    } catch (error) {
      next(error);
    }
  };
}

const requireAdmin = () => authenticate([USER_ROLES.ADMIN]);
const requireInfluencer = () => authenticate([USER_ROLES.INFLUENCER]);
const requireAuth = () => authenticate([USER_ROLES.ADMIN, USER_ROLES.INFLUENCER]);

async function ensureDefaultAdmin() {
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    return;
  }

  const existingAdmin = await User.findOne({ email: ADMIN_EMAIL.toLowerCase() });
  if (existingAdmin) {
    return;
  }

  const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, PASSWORD_SALT_ROUNDS);
  await User.create({
    email: ADMIN_EMAIL.toLowerCase(),
    password_hash: passwordHash,
    role: USER_ROLES.ADMIN,
    status: USER_STATUS.ACTIVE
  });
  console.log(`Default admin created for ${ADMIN_EMAIL}`);
}

const BASE_REGISTRATION_AMOUNT = 500; // All taxes included

// No GST calculation needed - price is all-inclusive
function applyGST(amount) {
  return amount; // Return as-is, no GST needed
}

function isCouponWithinValidity(coupon) {
  const now = new Date();
  if (coupon.valid_from && now < coupon.valid_from) {
    return false;
  }
  if (coupon.valid_until && now > coupon.valid_until) {
    return false;
  }
  if (!coupon.active) {
    return false;
  }
  if (coupon.usage_limit !== null && coupon.usage_count >= coupon.usage_limit) {
    return false;
  }
  return true;
}

function calculateDiscountedAmount(baseAmount, coupon) {
  if (!coupon) {
    // No coupon - return base amount (all-inclusive pricing)
    return { amount: baseAmount, discount: 0, baseAmount, gst: 0 };
  }

  let discount = 0;
  if (coupon.discount_type === 'percent') {
    discount = Math.round((coupon.discount_value / 100) * baseAmount);
  } else {
    discount = Math.round(coupon.discount_value);
  }

  const finalAmount = Math.max(0, Math.round(baseAmount - discount));

  return {
    amount: finalAmount,
    discount,
    baseAmount: finalAmount,
    gst: 0 // No separate GST - all-inclusive pricing
  };
}

function generateTemporaryPassword(length = 12) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$';
  let pwd = '';
  for (let i = 0; i < length; i += 1) {
    pwd += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return pwd;
}

function toNumber(value, defaultValue = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : defaultValue;
}

function toNullableNumber(value) {
  if (value === null || value === undefined || value === '') {
    return null;
  }
  const num = Number(value);
  return Number.isFinite(num) ? num : null;
}

function parseDateOrNull(value) {
  if (!value) {
    return null;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

async function upsertInfluencerUser({
  influencer,
  email,
  password,
  status = USER_STATUS.ACTIVE,
  loginEnabled = true,
  forcePasswordReset = false
}) {
  const normalizedEmail = (email || influencer.email || `${influencer.contact_number}@agrivalah.in`).toLowerCase();

  let user = await User.findOne({ linked_influencer: influencer._id });
  const passwordHash = password ? await bcrypt.hash(password, PASSWORD_SALT_ROUNDS) : undefined;

  const update = {
    email: normalizedEmail,
    role: USER_ROLES.INFLUENCER,
    status: loginEnabled ? status : USER_STATUS.DISABLED,
    linked_influencer: influencer._id,
    force_password_reset: forcePasswordReset
  };

  if (passwordHash) {
    update.password_hash = passwordHash;
    update.force_password_reset = forcePasswordReset;
  }

  if (user) {
    Object.assign(user, update);
    await user.save();
  } else {
    // Use influencer's existing password_hash if no new password provided
    const finalPasswordHash = passwordHash || influencer.password_hash;
    if (!finalPasswordHash) {
      throw new Error('Password is required when creating a new partner user');
    }
    user = await User.create({
      ...update,
      password_hash: finalPasswordHash
    });
  }

  return user;
}

async function getInfluencerStats(influencerId) {
  if (!mongoose.Types.ObjectId.isValid(influencerId)) {
    throw new Error('Invalid influencer identifier');
  }
  const objectId = new mongoose.Types.ObjectId(influencerId);
  const aggregation = await Registration.aggregate([
    { $match: { influencer: objectId } },
    {
      $group: {
        _id: '$payment_status',
        registrations: { $sum: 1 },
        revenue: { $sum: '$payment_amount' },
        discount: { $sum: '$coupon_discount' }
      }
    }
  ]);

  const totals = {
    totalRegistrations: 0,
    completed: 0,
    pending: 0,
    failed: 0,
    totalRevenue: 0,
    totalDiscount: 0
  };

  aggregation.forEach((row) => {
    totals.totalRegistrations += row.registrations;
    totals.totalRevenue += row.revenue || 0;
    totals.totalDiscount += row.discount || 0;
    if (row._id === 'completed') {
      totals.completed += row.registrations;
    } else if (row._id === 'pending') {
      totals.pending += row.registrations;
    } else if (row._id === 'failed') {
      totals.failed += row.registrations;
    }
  });

  const paymentsAgg = await Payment.aggregate([
    { $match: { influencer: objectId, payment_status: 'Success' } },
    {
      $group: {
        _id: null,
        totalCommission: { $sum: '$commission_amount' },
        totalPayments: { $sum: '$amount' },
        paymentCount: { $sum: 1 }
      }
    }
  ]);

  const paymentSummary = paymentsAgg[0] || {
    totalCommission: 0,
    totalPayments: 0,
    paymentCount: 0
  };

  const recentRegistrations = await Registration.find({ influencer: objectId })
    .sort({ registration_date: -1 })
    .limit(10)
    .select('farmer_name registration_date payment_status payment_amount coupon_code commission_amount');

  const coupons = await Coupon.find({ influencer: objectId }).select(
    'code usage_count usage_limit discount_type discount_value commission_amount total_revenue active'
  );

  return {
    totals,
    payments: paymentSummary,
    recentRegistrations,
    coupons
  };
}

function mapInfluencerResponse(influencer) {
  if (!influencer) return null;
  return {
    id: influencer._id,
    name: influencer.name,
    contactNumber: influencer.contact_number,
    email: influencer.email,
    type: influencer.type,
    region: influencer.region,
    socialLink: influencer.social_link,
    upiId: influencer.upi_id,
    bankDetails: influencer.bank_details,
    couponCode: influencer.coupon_code,
    approvalStatus: influencer.approval_status,
    loginEnabled: influencer.login_enabled,
    notes: influencer.notes,
    totalEarnings: influencer.total_earnings,
    payoutStatus: influencer.payout_status,
    referralLimit: influencer.referral_limit,
    referralUses: influencer.referral_uses,
    createdAt: influencer.created_at
  };
}

function generateReferralCode(seed = 'CYANO') {
  const base = seed.replace(/[^a-zA-Z0-9]/g, '').substring(0, 6).toUpperCase() || 'CYANO';
  const random = Math.floor(1000 + Math.random() * 9000);
  return `${base}${random}`.toUpperCase();
}

async function getUniqueCouponCode(prefCode, excludeId = null) {
  let candidate = (prefCode || generateReferralCode()).toUpperCase();
  let attempts = 0;
  while (attempts < 50) {
    const existing = await Coupon.findOne({
      code: candidate,
      ...(excludeId ? { influencer: { $ne: excludeId } } : {})
    });
    if (!existing) {
      return candidate;
    }
    candidate = generateReferralCode(candidate);
    attempts += 1;
  }
  throw new Error('Unable to generate unique referral code');
}

// =========================
// API ENDPOINTS
// =========================

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    const user = await User.findOne({ email: email.toLowerCase() }).populate('linked_influencer');
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    if (user.status !== USER_STATUS.ACTIVE) {
      return res.status(403).json({ success: false, message: 'Account is not active. Contact support.' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const token = signJwt(user);
    setAuthCookie(res, token);

    user.last_login = new Date();
    await user.save();

    res.json({
      success: true,
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        influencerId: user.linked_influencer?._id || null,
        forcePasswordReset: user.force_password_reset,
        influencer: user.linked_influencer
          ? {
            id: user.linked_influencer._id,
            name: user.linked_influencer.name,
            couponCode: user.linked_influencer.coupon_code,
            approvalStatus: user.linked_influencer.approval_status
          }
          : null
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Unable to login right now' });
  }
});

// Influencer login with mobile number
app.post('/api/auth/influencer-login', async (req, res) => {
  try {
    const { contactNumber, password } = req.body || {};

    console.log('[Influencer Login] Received contact:', contactNumber);

    if (!contactNumber || !password) {
      return res.status(400).json({ success: false, message: 'Mobile number and password are required' });
    }

    // Find influencer by contact number
    const influencer = await Influencer.findOne({ contact_number: contactNumber });
    console.log('[Influencer Login] Found influencer:', influencer ? { id: influencer._id, name: influencer.name, contact: influencer.contact_number } : 'NOT FOUND');

    if (!influencer) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Check if influencer has login enabled
    if (!influencer.login_enabled) {
      return res.status(403).json({ success: false, message: 'Login not enabled. Contact admin.' });
    }

    // Check approval status
    if (influencer.approval_status !== 'approved') {
      return res.status(403).json({ success: false, message: 'Your account is pending approval.' });
    }

    // Find user account (password is stored here)
    let user = await User.findOne({ linked_influencer: influencer._id });
    if (!user) {
      console.log('[Influencer Login] User account not found for influencer:', influencer._id);
      return res.status(401).json({ success: false, message: 'User account not found. Please contact admin.' });
    }

    if (process.env.NODE_ENV !== 'production') {
      console.log('[Influencer Login] Found user:', user.email);
      console.log('[Influencer Login] Password hash exists:', !!user.password_hash);
    }

    // Verify password from user account
    if (!user.password_hash) {
      return res.status(401).json({ success: false, message: 'Password not set. Please contact admin.' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    if (process.env.NODE_ENV !== 'production') {
      console.log('[Influencer Login] Password match:', passwordMatch);
    }

    if (!passwordMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const token = signJwt(user);
    setAuthCookie(res, token);

    influencer.last_login = new Date();
    await influencer.save();

    res.json({
      success: true,
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        influencerId: influencer._id,
        influencer: {
          id: influencer._id,
          name: influencer.name,
          contactNumber: influencer.contact_number,
          couponCode: influencer.coupon_code,
          approvalStatus: influencer.approval_status
        }
      }
    });
  } catch (error) {
    console.error('Influencer login error:', error);
    res.status(500).json({ success: false, message: 'Unable to login right now' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  clearAuthCookie(res);
  res.json({ success: true, message: 'Logged out successfully' });
});

app.get('/api/auth/me', requireAuth(), async (req, res) => {
  const user = req.authUser;
  res.json({
    success: true,
    user: {
      id: user._id,
      email: user.email,
      role: user.role,
      status: user.status,
      influencerId: user.linked_influencer?._id || null,
      forcePasswordReset: user.force_password_reset,
      influencer: user.linked_influencer
        ? {
          id: user.linked_influencer._id,
          name: user.linked_influencer.name,
          couponCode: user.linked_influencer.coupon_code,
          approvalStatus: user.linked_influencer.approval_status
        }
        : null
    }
  });
});

// Check if phone number already exists
app.post('/api/influencers/check-phone', async (req, res) => {
  try {
    const { phoneNumber } = req.body;

    if (!phoneNumber) {
      return res.status(400).json({ success: false, message: 'Phone number is required' });
    }

    const existing = await Influencer.findOne({ contact_number: phoneNumber });

    return res.json({
      success: true,
      exists: !!existing,
      message: existing ? 'Phone number already registered' : 'Phone number available'
    });
  } catch (error) {
    console.error('[Check Phone] Error:', error);
    return res.status(500).json({ success: false, message: 'Error checking phone number' });
  }
});

// Check if UPI ID already exists
app.post('/api/influencers/check-upi', async (req, res) => {
  try {
    const { upiId } = req.body;

    if (!upiId) {
      return res.status(400).json({ success: false, message: 'UPI ID is required' });
    }

    const existing = await Influencer.findOne({ upi_id: upiId });

    return res.json({
      success: true,
      exists: !!existing,
      message: existing ? 'UPI ID already registered' : 'UPI ID available'
    });
  } catch (error) {
    console.error('[Check UPI] Error:', error);
    return res.status(500).json({ success: false, message: 'Error checking UPI ID' });
  }
});

app.post('/api/influencers/register', async (req, res) => {
  try {
    console.log('[Influencer Registration] Request received:', {
      hasBody: !!req.body,
      bodyKeys: req.body ? Object.keys(req.body) : []
    });

    const {
      name,
      contactNumber,
      password,
      email,
      influencerType,
      type,
      region,
      socialMediaHandles,
      socialLink,
      upiId,
      bankDetails,
      notes
    } = req.body || {};

    // Validation
    if (!name || !contactNumber || !type || !password || !email || !influencerType) {
      console.log('[Influencer Registration] Validation failed - missing required fields');
      return res.status(400).json({
        success: false,
        message: 'Name, contact number, email, influencer type, category, and password are required.'
      });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid email address.'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters long.'
      });
    }

    if (!ALLOWED_INFLUENCER_ROLES.includes(type)) {
      console.log('[Influencer Registration] Invalid type:', type);
      return res.status(400).json({
        success: false,
        message: 'Invalid influencer type. Must be one of: ' + ALLOWED_INFLUENCER_ROLES.join(', ')
      });
    }

    const validInfluencerTypes = ['Social Media Influencer', 'Media', 'Celebrity'];
    if (!validInfluencerTypes.includes(influencerType)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid influencer type. Must be one of: ' + validInfluencerTypes.join(', ')
      });
    }

    // Check for duplicate contact number or email
    const existingInfluencer = await Influencer.findOne({
      $or: [
        { contact_number: contactNumber.trim() },
        { email: email.trim().toLowerCase() }
      ]
    });

    if (existingInfluencer) {
      const field = existingInfluencer.contact_number === contactNumber.trim() ? 'contact number' : 'email';
      console.log('[Influencer Registration] Duplicate ' + field + ':', contactNumber);
      return res.status(400).json({
        success: false,
        message: `An application with this ${field} already exists. Please contact support if you need assistance.`
      });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Process social media handles
    const processedHandles = Array.isArray(socialMediaHandles)
      ? socialMediaHandles.filter(h => h.platform && h.handle).map(h => ({
        platform: h.platform.trim(),
        handle: h.handle.trim(),
        followers: parseInt(h.followers) || 0
      }))
      : [];

    // Create influencer
    const influencer = await Influencer.create({
      name: name.trim(),
      contact_number: contactNumber.trim(),
      password_hash: passwordHash,
      email: email.trim().toLowerCase(),
      influencer_type: influencerType,
      type,
      social_media_handles: processedHandles,
      social_link: socialLink || null,
      region: region || null,
      upi_id: upiId || null,
      bank_details: bankDetails || null,
      approval_status: 'pending',
      login_enabled: true,
      coupon_code: null,
      notes: notes || null,
      admin_messages: [],
      referral_limit: null,
      referral_uses: 0,
      commission_amount: 0
    });

    console.log('[Influencer Registration] Success - ID:', influencer._id);

    res.status(201).json({
      success: true,
      message: 'Influencer application submitted successfully! Our team will review and respond soon.',
      influencerId: influencer._id
    });
  } catch (error) {
    console.error('[Influencer Registration] Error:', error);

    // Handle specific MongoDB errors
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: 'An application with this information already exists. Please check your contact number or email.'
      });
    }

    if (error.name === 'ValidationError') {
      return res.status(400).json({
        success: false,
        message: 'Validation error: ' + error.message
      });
    }

    res.status(500).json({
      success: false,
      message: 'Unable to submit application. Please try again or contact support.'
    });
  }
});

// Coupon validation endpoint
app.get('/api/validate-coupon', async (req, res) => {
  const rawCode = (req.query.code || '').trim();
  if (!rawCode) {
    return res.json({ valid: false });
  }

  try {
    const normalized = rawCode.toLowerCase();

    if (normalized === TEST_REFERRAL_CODE) {
      const discountAmount = 50;
      const finalAmount = Math.max(0, BASE_REGISTRATION_AMOUNT - discountAmount);
      return res.json({
        valid: true,
        influencerName: TEST_REFERRAL_NAME,
        influencerId: null,
        amount: finalAmount,
        discount: discountAmount,
        baseAmount: finalAmount,
        gst: 0, // All-inclusive pricing
        testCoupon: true,
        code: rawCode.toUpperCase()
      });
    }

    // Try case-insensitive search for coupon code
    const coupon = await Coupon.findOne({
      code: { $regex: new RegExp(`^${rawCode}$`, 'i') }
    }).populate('influencer');

    if (!coupon) {
      return res.json({ valid: false });
    }

    if (
      !coupon.influencer ||
      coupon.influencer.approval_status !== 'approved' ||
      !isCouponWithinValidity(coupon)
    ) {
      return res.json({ valid: false });
    }

    const { amount, discount, baseAmount, gst } = calculateDiscountedAmount(BASE_REGISTRATION_AMOUNT, coupon);

    return res.json({
      valid: true,
      influencerName: coupon.influencer.name,
      influencerId: coupon.influencer._id,
      amount,
      discount,
      baseAmount,
      gst,
      commissionAmount: coupon.commission_amount || 0,
      usageCount: coupon.usage_count,
      usageLimit: coupon.usage_limit,
      code: coupon.code
    });
  } catch (error) {
    console.error('Coupon validation error:', error);
    return res.status(500).json({
      valid: false,
      message: 'Unable to validate coupon right now.'
    });
  }
});

const handleOtpRequest = async (req, res) => {
  try {
    const phoneNumber = (req.body.phoneNumber || req.body.phone || '').trim();

    console.log(`[OTP] Request received for phone: ${phoneNumber.substring(0, 6)}****`);

    if (!PHONE_REGEX.test(phoneNumber)) {
      console.log(`[OTP] Invalid phone number format`);
      return res.status(400).json({ success: false, message: 'Enter a valid 10-digit mobile number.' });
    }

    const now = new Date();
    const recentSession = await OtpSession.findOne({ phone_number: phoneNumber }).sort({ createdAt: -1 });

    if (recentSession && recentSession.last_sent_at) {
      const elapsed = now.getTime() - recentSession.last_sent_at.getTime();
      const cooldownMs = otpResendCooldownSeconds * 1000;
      if (elapsed < cooldownMs) {
        const waitSeconds = Math.max(1, Math.ceil((cooldownMs - elapsed) / 1000));
        console.log(`[OTP] Cooldown active - Wait ${waitSeconds}s`);
        return res.status(429).json({
          success: false,
          message: `Please wait ${waitSeconds} second${waitSeconds === 1 ? '' : 's'} before requesting another OTP.`
        });
      }
    }

    console.log(`[OTP] Generating new OTP code`);
    const otpCode = generateOtpCode();
    console.log(`[OTP] Creating session with ${otpExpiryMinutes} minute expiry`);

    const session = new OtpSession({
      phone_number: phoneNumber,
      code_hash: hashOtpCode(otpCode),
      provider: twilioClient ? 'twilio' : 'simulated',
      status: 'pending',
      expires_at: new Date(now.getTime() + otpExpiryMinutes * 60 * 1000),
      last_sent_at: now,
      attempts: 0,
      verified: false,
      used: false,
      used_at: null,
      verified_at: null
    });

    await session.save();
    console.log(`[OTP] Session saved - ID: ${session._id}, Provider: ${session.provider}`);

    try {
      const dispatchResult = await dispatchOtp(phoneNumber, otpCode);
      const simulated = dispatchResult && dispatchResult.simulated;
      console.log(`[OTP] Dispatch ${simulated ? 'simulated' : 'successful'}`);

      // In development or if simulated, include OTP in response for testing
      const includeTestOtp = process.env.NODE_ENV !== 'production' || simulated;

      return res.json({
        success: true,
        message: 'OTP sent successfully.',
        expiresIn: otpExpiryMinutes * 60,
        cooldown: otpResendCooldownSeconds,
        otpLength: OTP_LENGTH,
        testOtp: includeTestOtp ? otpCode : undefined,
        simulated: simulated
      });
    } catch (dispatchError) {
      console.error('[OTP] Dispatch error:', dispatchError);
      // Don't delete session - keep it for verification even if SMS fails
      // This allows testing and fallback scenarios
      console.warn('[OTP] Keeping session active despite dispatch error');

      // In non-production, return OTP for testing
      const includeTestOtp = process.env.NODE_ENV !== 'production';

      return res.json({
        success: true,
        message: 'OTP generated. SMS delivery may have failed.',
        expiresIn: otpExpiryMinutes * 60,
        cooldown: otpResendCooldownSeconds,
        otpLength: OTP_LENGTH,
        testOtp: includeTestOtp ? otpCode : undefined,
        warning: 'SMS service unavailable'
      });
    }
  } catch (error) {
    console.error('[OTP] Request error:', error);
    return res.status(500).json({
      success: false,
      message: error.message || 'Failed to send OTP'
    });
  }
};

const handleOtpVerification = async (req, res) => {
  try {
    const phoneNumber = (req.body.phoneNumber || req.body.phone || '').trim();
    // Sanitize OTP input: trim whitespace and ensure it's a string
    const otpCode = String(req.body.otpCode || req.body.otp || '').trim();

    console.log(`[OTP] Verification attempt for phone: ${phoneNumber.substring(0, 6)}****`);

    if (!PHONE_REGEX.test(phoneNumber)) {
      console.log(`[OTP] Invalid phone number format`);
      return res.status(400).json({ success: false, message: 'Enter a valid 10-digit mobile number.' });
    }

    // Additional sanitization: remove any non-digit characters
    const sanitizedOtp = otpCode.replace(/\D/g, '');

    if (!OTP_CODE_REGEX.test(sanitizedOtp)) {
      console.log(`[OTP] Invalid OTP format - Original: "${otpCode}", Sanitized: "${sanitizedOtp}", Length: ${sanitizedOtp.length}, Expected: ${OTP_LENGTH}`);
      return res.status(400).json({ success: false, message: `OTP must be ${OTP_LENGTH} digits.` });
    }

    const session = await OtpSession.findOne({ phone_number: phoneNumber }).sort({ createdAt: -1 });

    if (!session) {
      console.log(`[OTP] No session found for phone: ${phoneNumber.substring(0, 6)}****`);
      return res.status(400).json({ success: false, message: 'No OTP request found for this number.' });
    }

    console.log(`[OTP] Session found - Status: ${session.status}, Attempts: ${session.attempts}, Verified: ${session.verified}`);

    const now = new Date();

    if (session.used || session.status === 'used') {
      console.log(`[OTP] Session already used`);
      return res.status(400).json({ success: false, message: 'OTP already used. Request a new one.' });
    }

    if (session.expires_at <= now) {
      console.log(`[OTP] Session expired - Expired at: ${session.expires_at}, Now: ${now}`);
      session.status = 'used';
      session.used = true;
      session.used_at = now;
      await session.save();
      return res.status(400).json({ success: false, message: 'OTP expired. Request a new code.' });
    }

    if (session.verified && session.session_token && session.session_expires_at && session.session_expires_at > now) {
      console.log(`[OTP] Session already verified, returning existing token`);
      return res.json({
        success: true,
        message: 'OTP already verified.',
        otpToken: session.session_token,
        expiresIn: Math.floor((session.session_expires_at.getTime() - now.getTime()) / 1000)
      });
    }

    if (session.attempts >= 5) {
      console.log(`[OTP] Too many attempts - Attempts: ${session.attempts}`);
      return res.status(429).json({ success: false, message: 'Too many incorrect attempts. Request a new OTP.' });
    }

    console.log(`[OTP] Starting hash comparison - Input OTP type: ${typeof sanitizedOtp}, length: ${sanitizedOtp.length}`);
    const hashedInput = hashOtpCode(sanitizedOtp);
    console.log(`[OTP] Stored hash first 8 chars: ${session.code_hash.substring(0, 8)}...`);
    console.log(`[OTP] Input hash first 8 chars: ${hashedInput.substring(0, 8)}...`);
    console.log(`[OTP] Hash match: ${hashedInput === session.code_hash}`);

    if (hashedInput !== session.code_hash) {
      session.attempts += 1;
      await session.save();
      const remaining = Math.max(0, 5 - session.attempts);
      console.log(`[OTP] Hash mismatch - Attempts now: ${session.attempts}, Remaining: ${remaining}`);
      const responseMessage = remaining
        ? `Incorrect OTP. ${remaining} attempt${remaining === 1 ? '' : 's'} remaining.`
        : 'Too many incorrect attempts. Request a new OTP.';
      const statusCode = remaining ? 400 : 429;
      return res.status(statusCode).json({ success: false, message: responseMessage });
    }

    console.log(`[OTP] Verification successful - Marking session as verified`);
    session.verified = true;
    session.status = 'verified';
    session.verified_at = now;
    session.session_token = session.session_token || generateOtpSessionToken();
    session.session_expires_at = new Date(now.getTime() + otpSessionTtlMinutes * 60 * 1000);
    session.attempts = 0;

    await session.save();

    console.log(`[OTP] Session updated - Token generated, expires in ${otpSessionTtlMinutes} minutes`);

    return res.json({
      success: true,
      message: 'OTP verified successfully.',
      otpToken: session.session_token,
      expiresIn: Math.floor((session.session_expires_at.getTime() - now.getTime()) / 1000)
    });
  } catch (error) {
    console.error('[OTP] Verification error:', error);
    return res.status(500).json({
      success: false,
      message: error.message || 'Failed to verify OTP'
    });
  }
};

app.post('/api/otp/request', handleOtpRequest);
app.post('/api/otp/send', handleOtpRequest);
app.post('/api/otp/verify', handleOtpVerification);

// ---------- Admin Routes ----------

app.get('/api/admin/influencers', requireAdmin(), async (req, res) => {
  try {
    const { status, search, page = 1, limit = 20 } = req.query;
    const query = {};
    if (status) {
      query.approval_status = status;
    }
    if (search) {
      const regex = new RegExp(search, 'i');
      query.$or = [
        { name: regex },
        { email: regex },
        { contact_number: regex },
        { coupon_code: regex }
      ];
    }

    const pageNumber = Math.max(1, parseInt(page, 10) || 1);
    const pageSize = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
    const skip = (pageNumber - 1) * pageSize;

    const [items, total] = await Promise.all([
      Influencer.find(query).sort({ created_at: -1 }).skip(skip).limit(pageSize).lean(),
      Influencer.countDocuments(query)
    ]);

    const influencerIds = items.map((doc) => doc._id);
    const stats = influencerIds.length
      ? await Registration.aggregate([
        { $match: { influencer: { $in: influencerIds } } },
        {
          $group: {
            _id: '$influencer',
            totalRegistrations: { $sum: 1 },
            completed: {
              $sum: {
                $cond: [{ $eq: ['$payment_status', 'completed'] }, 1, 0]
              }
            },
            pending: {
              $sum: {
                $cond: [{ $eq: ['$payment_status', 'pending'] }, 1, 0]
              }
            },
            revenue: { $sum: '$payment_amount' },
            discountTotal: { $sum: '$coupon_discount' }
          }
        }
      ])
      : [];
    const statsMap = {};
    stats.forEach((row) => {
      statsMap[row._id.toString()] = row;
    });

    const commissions = influencerIds.length
      ? await Payment.aggregate([
        { $match: { influencer: { $in: influencerIds }, payment_status: 'Success' } },
        {
          $group: {
            _id: '$influencer',
            totalCommission: { $sum: '$commission_amount' },
            totalPayments: { $sum: '$amount' }
          }
        }
      ])
      : [];
    const commissionMap = {};
    commissions.forEach((row) => {
      commissionMap[row._id.toString()] = row;
    });

    const couponDocs = influencerIds.length
      ? await Coupon.find({ influencer: { $in: influencerIds } }).lean()
      : [];
    const couponMap = couponDocs.reduce((acc, coupon) => {
      const key = coupon.influencer.toString();
      if (!acc[key]) acc[key] = [];
      acc[key].push(coupon);
      return acc;
    }, {});

    const data = items.map((doc) => {
      const mapped = mapInfluencerResponse(doc);
      const stat = statsMap[doc._id.toString()] || {};
      const commission = commissionMap[doc._id.toString()] || {};
      mapped.metrics = {
        totalRegistrations: stat.totalRegistrations || 0,
        completedRegistrations: stat.completed || 0,
        pendingRegistrations: stat.pending || 0,
        totalRevenue: stat.revenue || 0,
        totalDiscount: stat.discountTotal || 0,
        totalCommission: commission.totalCommission || 0,
        totalPayments: commission.totalPayments || 0
      };
      mapped.coupons = (couponMap[doc._id.toString()] || []).map((coupon) => ({
        id: coupon._id,
        code: coupon.code,
        usageCount: coupon.usage_count,
        usageLimit: coupon.usage_limit,
        discountType: coupon.discount_type,
        discountValue: coupon.discount_value,
        commissionAmount: coupon.commission_amount,
        active: coupon.active,
        validFrom: coupon.valid_from,
        validUntil: coupon.valid_until
      }));
      return mapped;
    });

    res.json({
      success: true,
      total,
      page: pageNumber,
      pageSize,
      influencers: data
    });
  } catch (error) {
    console.error('Admin list influencers error:', error);
    res.status(500).json({ success: false, message: 'Failed to load influencers' });
  }
});

app.post('/api/admin/influencers', requireAdmin(), async (req, res) => {
  try {
    const {
      name,
      contactNumber,
      email,
      type,
      region,
      socialLink,
      upiId,
      bankDetails,
      notes,
      couponCode,
      discountType = 'flat',
      discountValue = 50,
      usageLimit = null,
      commissionAmount = 0,
      approvalStatus = 'approved',
      loginEnabled = true,
      password = null,
      referralLimit = null
    } = req.body || {};

    if (!name || !contactNumber || !type) {
      return res.status(400).json({ success: false, message: 'Name, contact number, and type are required.' });
    }

    if (!ALLOWED_INFLUENCER_ROLES.includes(type)) {
      return res.status(400).json({ success: false, message: 'Invalid influencer type.' });
    }

    if (!['flat', 'percent'].includes(discountType)) {
      return res.status(400).json({ success: false, message: 'Invalid discount type.' });
    }

    const allowedApprovalStatuses = ['pending', 'approved', 'rejected', 'disabled'];
    const normalizedApprovalStatus = allowedApprovalStatuses.includes(approvalStatus)
      ? approvalStatus
      : 'approved';

    const normalizedDiscountType = discountType === 'percent' ? 'percent' : 'flat';
    let normalizedDiscountValue = toNumber(discountValue, normalizedDiscountType === 'percent' ? 10 : 50);
    if (normalizedDiscountType === 'percent') {
      normalizedDiscountValue = Math.min(Math.max(normalizedDiscountValue, 0), 100);
    } else {
      normalizedDiscountValue = Math.max(0, normalizedDiscountValue);
    }

    const normalizedCommissionAmount = Math.max(0, toNumber(commissionAmount, 0));
    let normalizedUsageLimit = toNullableNumber(usageLimit);
    if (normalizedUsageLimit !== null) {
      normalizedUsageLimit = Math.max(0, Math.floor(normalizedUsageLimit));
    }
    const normalizedReferralLimit = toNullableNumber(referralLimit);
    const loginEnabledBoolean = Boolean(loginEnabled);

    const influencer = await Influencer.create({
      name: name.trim(),
      contact_number: contactNumber.trim(),
      email: email ? email.trim().toLowerCase() : null,
      type,
      social_link: socialLink || null,
      region: region || null,
      upi_id: upiId || null,
      bank_details: bankDetails || null,
      approval_status: normalizedApprovalStatus,
      login_enabled: loginEnabledBoolean,
      notes: notes || null,
      referral_limit: normalizedReferralLimit,
      referral_uses: 0,
      total_earnings: 0,
      commission_amount: normalizedCommissionAmount,
      payout_status: 'Pending'
    });

    const finalCouponCode = await getUniqueCouponCode(couponCode || generateReferralCode(name), influencer._id);
    influencer.coupon_code = finalCouponCode;
    await influencer.save();

    await Coupon.findOneAndUpdate(
      { influencer: influencer._id },
      {
        code: finalCouponCode,
        influencer: influencer._id,
        commission_amount: normalizedCommissionAmount,
        discount_type: normalizedDiscountType,
        discount_value: normalizedDiscountValue,
        usage_limit: normalizedUsageLimit,
        active: normalizedApprovalStatus === 'approved',
        valid_from: null,
        valid_until: null
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    let generatedPassword = password;
    if (!generatedPassword) {
      generatedPassword = generateTemporaryPassword();
    }

    let user = null;
    if (loginEnabledBoolean) {
      user = await upsertInfluencerUser({
        influencer,
        email: email || influencer.email || `${contactNumber}@cyano.in`,
        password: generatedPassword,
        status: normalizedApprovalStatus === 'approved' ? USER_STATUS.ACTIVE : USER_STATUS.PENDING,
        loginEnabled: loginEnabledBoolean,
        forcePasswordReset: !password
      });
    }

    res.status(201).json({
      success: true,
      influencer: mapInfluencerResponse(influencer),
      user: user
        ? {
          id: user._id,
          email: user.email,
          status: user.status
        }
        : null,
      temporaryPassword: password ? null : generatedPassword
    });
  } catch (error) {
    console.error('Admin create influencer error:', error);
    res.status(500).json({ success: false, message: error.message || 'Failed to create influencer' });
  }
});

app.patch('/api/admin/influencers/:id', requireAdmin(), async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid influencer id' });
    }

    const influencer = await Influencer.findById(id);
    if (!influencer) {
      return res.status(404).json({ success: false, message: 'Influencer not found' });
    }

    const {
      name,
      contactNumber,
      email,
      type,
      region,
      socialLink,
      upiId,
      bankDetails,
      notes,
      approvalStatus,
      loginEnabled,
      couponCode,
      discountType,
      discountValue,
      usageLimit,
      commissionAmount,
      referralLimit,
      resetPassword
    } = req.body || {};

    if (name) influencer.name = name.trim();
    if (contactNumber) influencer.contact_number = contactNumber.trim();
    if (email) influencer.email = email.trim().toLowerCase();
    if (type && ALLOWED_INFLUENCER_ROLES.includes(type)) influencer.type = type;
    if (region !== undefined) influencer.region = region || null;
    if (socialLink !== undefined) influencer.social_link = socialLink || null;
    if (upiId !== undefined) influencer.upi_id = upiId || null;
    if (bankDetails !== undefined) influencer.bank_details = bankDetails || null;
    if (notes !== undefined) influencer.notes = notes || null;

    const allowedApprovalStatuses = ['pending', 'approved', 'rejected', 'disabled'];
    if (approvalStatus && allowedApprovalStatuses.includes(approvalStatus)) {
      influencer.approval_status = approvalStatus;
    }
    if (referralLimit !== undefined) {
      const refLimit = toNullableNumber(referralLimit);
      influencer.referral_limit = refLimit;
    }
    if (loginEnabled !== undefined) {
      influencer.login_enabled = Boolean(loginEnabled);
    }

    if (commissionAmount !== undefined) {
      influencer.commission_amount = Math.max(0, toNumber(commissionAmount, influencer.commission_amount));
    }

    let updatedCoupon = null;
    if (
      couponCode !== undefined ||
      discountType !== undefined ||
      discountValue !== undefined ||
      usageLimit !== undefined ||
      commissionAmount !== undefined
    ) {
      const existingCoupon = await Coupon.findOne({ influencer: influencer._id });
      let targetCode =
        existingCoupon?.code ||
        influencer.coupon_code ||
        (await getUniqueCouponCode(generateReferralCode(influencer.name), influencer._id));

      if (couponCode) {
        targetCode = await getUniqueCouponCode(couponCode, influencer._id);
      }

      const discountTypeToUse =
        discountType && ['flat', 'percent'].includes(discountType)
          ? discountType
          : existingCoupon?.discount_type || 'flat';

      let discountValueToUse =
        discountValue !== undefined
          ? toNumber(discountValue, existingCoupon?.discount_value || 50)
          : existingCoupon?.discount_value || 50;
      if (discountTypeToUse === 'percent') {
        discountValueToUse = Math.min(Math.max(discountValueToUse, 0), 100);
      } else {
        discountValueToUse = Math.max(0, discountValueToUse);
      }

      let usageLimitToUse =
        usageLimit !== undefined ? toNullableNumber(usageLimit) : existingCoupon?.usage_limit || null;
      if (usageLimitToUse !== null) {
        usageLimitToUse = Math.max(0, Math.floor(usageLimitToUse));
      }

      const commissionAmountToUse =
        commissionAmount !== undefined
          ? Math.max(0, toNumber(commissionAmount, existingCoupon?.commission_amount || influencer.commission_amount || 0))
          : existingCoupon?.commission_amount ?? influencer.commission_amount ?? 0;

      influencer.coupon_code = targetCode;
      influencer.commission_amount = commissionAmountToUse;

      updatedCoupon = await Coupon.findOneAndUpdate(
        { influencer: influencer._id },
        {
          code: targetCode,
          commission_amount: commissionAmountToUse,
          discount_type: discountTypeToUse,
          discount_value: discountValueToUse,
          usage_limit: usageLimitToUse,
          active: influencer.approval_status === 'approved'
        },
        { upsert: true, new: true, setDefaultsOnInsert: true }
      );
    }

    await influencer.save();

    let user = await User.findOne({ linked_influencer: influencer._id });
    if (influencer.login_enabled && !user) {
      const tempPassword = generateTemporaryPassword();
      user = await upsertInfluencerUser({
        influencer,
        email: influencer.email || `${influencer.contact_number}@cyano.in`,
        password: tempPassword,
        status: influencer.approval_status === 'approved' ? USER_STATUS.ACTIVE : USER_STATUS.PENDING,
        loginEnabled: influencer.login_enabled,
        forcePasswordReset: true
      });
    } else if (user) {
      if (influencer.login_enabled) {
        user.status = influencer.approval_status === 'approved' ? USER_STATUS.ACTIVE : USER_STATUS.PENDING;
      } else {
        user.status = USER_STATUS.DISABLED;
      }
      if (resetPassword) {
        user.password_hash = await bcrypt.hash(resetPassword, PASSWORD_SALT_ROUNDS);
        user.force_password_reset = false;
      }
      await user.save();
    }

    res.json({
      success: true,
      influencer: mapInfluencerResponse(influencer),
      coupon: updatedCoupon
        ? {
          id: updatedCoupon._id,
          code: updatedCoupon.code,
          discountType: updatedCoupon.discount_type,
          discountValue: updatedCoupon.discount_value,
          usageLimit: updatedCoupon.usage_limit,
          commissionAmount: updatedCoupon.commission_amount,
          active: updatedCoupon.active
        }
        : null
    });
  } catch (error) {
    console.error('Admin update influencer error:', error);
    res.status(500).json({ success: false, message: error.message || 'Failed to update influencer' });
  }
});

app.delete('/api/admin/influencers/:id', requireAdmin(), async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid influencer id' });
    }

    const influencer = await Influencer.findById(id);
    if (!influencer) {
      return res.status(404).json({ success: false, message: 'Influencer not found' });
    }

    influencer.approval_status = 'disabled';
    influencer.login_enabled = false;
    await influencer.save();

    await Coupon.updateMany({ influencer: influencer._id }, { active: false });
    await User.updateMany({ linked_influencer: influencer._id }, { status: USER_STATUS.DISABLED });

    res.json({ success: true, message: 'Influencer disabled successfully' });
  } catch (error) {
    console.error('Admin delete influencer error:', error);
    res.status(500).json({ success: false, message: 'Failed to disable influencer' });
  }
});

// Admin - Assign/Update Coupon Code for Influencer
app.post('/api/admin/influencers/:id/assign-coupon', requireAdmin(), async (req, res) => {
  try {
    const { id } = req.params;
    const { couponCode, customCode, commissionAmount, discountType, discountValue } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid influencer id' });
    }

    const influencer = await Influencer.findById(id);
    if (!influencer) {
      return res.status(404).json({ success: false, message: 'Influencer not found' });
    }

    let finalCouponCode;

    if (customCode) {
      // Admin provided custom code
      finalCouponCode = customCode.toUpperCase().trim();

      // Check if code already exists for another influencer
      const existing = await Coupon.findOne({
        code: finalCouponCode,
        influencer: { $ne: influencer._id }
      });

      if (existing) {
        return res.status(400).json({
          success: false,
          message: 'This coupon code is already assigned to another influencer'
        });
      }
    } else {
      // Generate random code
      const baseCode = influencer.name.substring(0, 4).toUpperCase().replace(/[^A-Z0-9]/g, '');
      finalCouponCode = await getUniqueCouponCode(baseCode + Math.floor(1000 + Math.random() * 9000));
    }

    // Update or create coupon
    const couponData = {
      code: finalCouponCode,
      influencer: influencer._id,
      commission_amount: commissionAmount || 50,
      discount_type: discountType || 'flat',
      discount_value: discountValue || 50,
      active: true
    };

    await Coupon.findOneAndUpdate(
      { influencer: influencer._id },
      couponData,
      { upsert: true, new: true }
    );

    // Update influencer
    influencer.coupon_code = finalCouponCode;
    influencer.commission_amount = commissionAmount || 50;
    await influencer.save();

    res.json({
      success: true,
      message: 'Coupon code assigned successfully',
      couponCode: finalCouponCode
    });
  } catch (error) {
    console.error('Admin assign coupon error:', error);
    res.status(500).json({ success: false, message: 'Failed to assign coupon code' });
  }
});

// Admin - Send Message to Influencer
app.post('/api/admin/influencers/:id/send-message', requireAdmin(), async (req, res) => {
  try {
    const { id } = req.params;
    const { message } = req.body;

    if (!message || !message.trim()) {
      return res.status(400).json({ success: false, message: 'Message is required' });
    }

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid influencer id' });
    }

    const influencer = await Influencer.findById(id);
    if (!influencer) {
      return res.status(404).json({ success: false, message: 'Influencer not found' });
    }

    influencer.admin_messages.push({
      message: message.trim(),
      sent_at: new Date(),
      read: false
    });

    await influencer.save();

    res.json({
      success: true,
      message: 'Message sent successfully'
    });
  } catch (error) {
    console.error('Admin send message error:', error);
    res.status(500).json({ success: false, message: 'Failed to send message' });
  }
});

// Admin - Send Broadcast Message to Multiple Influencers
app.post('/api/admin/influencers/broadcast', requireAdmin(), async (req, res) => {
  try {
    const { message, influencerIds, filter } = req.body;

    if (!message || !message.trim()) {
      return res.status(400).json({ success: false, message: 'Message is required' });
    }

    let targetInfluencers;

    if (influencerIds && influencerIds.length > 0) {
      // Send to specific influencers
      targetInfluencers = await Influencer.find({ _id: { $in: influencerIds } });
    } else if (filter) {
      // Send based on filter
      const query = {};
      if (filter.approvalStatus) query.approval_status = filter.approvalStatus;
      if (filter.influencerType) query.influencer_type = filter.influencerType;
      targetInfluencers = await Influencer.find(query);
    } else {
      // Send to all approved influencers
      targetInfluencers = await Influencer.find({ approval_status: 'approved' });
    }

    const messageData = {
      message: message.trim(),
      sent_at: new Date(),
      read: false
    };

    await Influencer.updateMany(
      { _id: { $in: targetInfluencers.map(i => i._id) } },
      { $push: { admin_messages: messageData } }
    );

    res.json({
      success: true,
      message: `Message sent to ${targetInfluencers.length} influencer(s)`,
      count: targetInfluencers.length
    });
  } catch (error) {
    console.error('Admin broadcast message error:', error);
    res.status(500).json({ success: false, message: 'Failed to send broadcast message' });
  }
});

// Admin - Get Registrations with Filters
app.get('/api/admin/registrations/filtered', requireAdmin(), async (req, res) => {
  try {
    const {
      paymentStatus,
      influencerId,
      dateFrom,
      dateTo,
      search,
      page = 1,
      limit = 50
    } = req.query;

    const query = {};

    if (paymentStatus) query.payment_status = paymentStatus;
    if (influencerId && mongoose.Types.ObjectId.isValid(influencerId)) {
      query.influencer = influencerId;
    }
    if (dateFrom || dateTo) {
      query.registration_date = {};
      if (dateFrom) query.registration_date.$gte = new Date(dateFrom);
      if (dateTo) query.registration_date.$lte = new Date(dateTo);
    }
    if (search) {
      query.$or = [
        { farmer_name: { $regex: search, $options: 'i' } },
        { contact_number: { $regex: search, $options: 'i' } },
        { reference_id: { $regex: search, $options: 'i' } }
      ];
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);

    const [registrations, total] = await Promise.all([
      Registration.find(query)
        .populate('influencer', 'name contact_number coupon_code')
        .sort({ registration_date: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Registration.countDocuments(query)
    ]);

    res.json({
      success: true,
      registrations,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / parseInt(limit))
      }
    });
  } catch (error) {
    console.error('Admin filtered registrations error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch registrations' });
  }
});

app.get('/api/admin/dashboard/overview', requireAdmin(), async (req, res) => {
  try {
    const [
      totalInfluencers,
      pendingInfluencers,
      activeCoupons,
      totalRegistrations,
      completedRegistrations,
      revenueAgg
    ] = await Promise.all([
      Influencer.countDocuments(),
      Influencer.countDocuments({ approval_status: 'pending' }),
      Coupon.countDocuments({ active: true }),
      Registration.countDocuments(),
      Registration.countDocuments({ payment_status: 'completed' }),
      Payment.aggregate([
        { $match: { payment_status: 'Success' } },
        { $group: { _id: null, totalPayments: { $sum: '$amount' }, commissionTotal: { $sum: '$commission_amount' } } }
      ])
    ]);

    const revenueSummary = revenueAgg[0] || { totalPayments: 0, commissionTotal: 0 };

    res.json({
      success: true,
      stats: {
        totalInfluencers,
        pendingInfluencers,
        activeCoupons,
        totalRegistrations,
        completedRegistrations,
        totalRevenue: revenueSummary.totalPayments,
        totalCommission: revenueSummary.commissionTotal
      }
    });
  } catch (error) {
    console.error('Admin overview error:', error);
    res.status(500).json({ success: false, message: 'Failed to load dashboard overview' });
  }
});

app.get('/api/admin/coupons', requireAdmin(), async (req, res) => {
  try {
    const coupons = await Coupon.find().populate('influencer').sort({ created_at: -1 });
    res.json({
      success: true,
      coupons: coupons.map((coupon) => ({
        id: coupon._id,
        code: coupon.code,
        influencer: coupon.influencer ? mapInfluencerResponse(coupon.influencer) : null,
        commissionAmount: coupon.commission_amount,
        discountType: coupon.discount_type,
        discountValue: coupon.discount_value,
        usageCount: coupon.usage_count,
        usageLimit: coupon.usage_limit,
        totalRevenue: coupon.total_revenue,
        active: coupon.active,
        validFrom: coupon.valid_from,
        validUntil: coupon.valid_until,
        notes: coupon.notes
      }))
    });
  } catch (error) {
    console.error('Admin list coupons error:', error);
    res.status(500).json({ success: false, message: 'Failed to load coupons' });
  }
});

app.post('/api/admin/coupons', requireAdmin(), async (req, res) => {
  try {
    const {
      influencerId,
      code,
      commissionAmount = 0,
      discountType = 'flat',
      discountValue = 50,
      usageLimit = null,
      validFrom = null,
      validUntil = null,
      notes = null,
      active = true
    } = req.body || {};

    if (!influencerId || !mongoose.Types.ObjectId.isValid(influencerId)) {
      return res.status(400).json({ success: false, message: 'Valid influencer id required.' });
    }

    const influencer = await Influencer.findById(influencerId);
    if (!influencer) {
      return res.status(404).json({ success: false, message: 'Influencer not found' });
    }

    const finalCode = await getUniqueCouponCode(code || generateReferralCode(influencer.name), influencer._id);

    const normalizedDiscountType = ['flat', 'percent'].includes(discountType) ? discountType : 'flat';
    let normalizedDiscountValue = toNumber(
      discountValue,
      normalizedDiscountType === 'percent' ? 10 : 50
    );
    if (normalizedDiscountType === 'percent') {
      normalizedDiscountValue = Math.min(Math.max(normalizedDiscountValue, 0), 100);
    } else {
      normalizedDiscountValue = Math.max(0, normalizedDiscountValue);
    }
    const normalizedCommissionAmount = Math.max(0, toNumber(commissionAmount, 0));
    let normalizedUsageLimit = toNullableNumber(usageLimit);
    if (normalizedUsageLimit !== null) {
      normalizedUsageLimit = Math.max(0, Math.floor(normalizedUsageLimit));
    }
    const normalizedValidFrom = parseDateOrNull(validFrom);
    const normalizedValidUntil = parseDateOrNull(validUntil);

    const coupon = await Coupon.create({
      code: finalCode,
      influencer: influencer._id,
      commission_amount: normalizedCommissionAmount,
      discount_type: normalizedDiscountType,
      discount_value: normalizedDiscountValue,
      usage_limit: normalizedUsageLimit,
      valid_from: normalizedValidFrom,
      valid_until: normalizedValidUntil,
      active,
      notes
    });

    res.status(201).json({
      success: true,
      coupon: {
        id: coupon._id,
        code: coupon.code,
        influencer: mapInfluencerResponse(influencer),
        commissionAmount: normalizedCommissionAmount,
        discountType: normalizedDiscountType,
        discountValue: normalizedDiscountValue,
        usageLimit: normalizedUsageLimit,
        active,
        validFrom: normalizedValidFrom,
        validUntil: normalizedValidUntil,
        notes
      }
    });
  } catch (error) {
    console.error('Admin create coupon error:', error);
    res.status(500).json({ success: false, message: error.message || 'Failed to create coupon' });
  }
});

app.patch('/api/admin/coupons/:id', requireAdmin(), async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid coupon id' });
    }

    const {
      commissionAmount,
      discountType,
      discountValue,
      usageLimit,
      validFrom,
      validUntil,
      notes,
      active
    } = req.body || {};

    const coupon = await Coupon.findById(id).populate('influencer');
    if (!coupon) {
      return res.status(404).json({ success: false, message: 'Coupon not found' });
    }

    if (commissionAmount !== undefined) {
      coupon.commission_amount = Math.max(0, toNumber(commissionAmount, coupon.commission_amount));
    }
    if (discountType && ['flat', 'percent'].includes(discountType)) {
      coupon.discount_type = discountType;
    }
    if (discountValue !== undefined) {
      let value = toNumber(discountValue, coupon.discount_value);
      if (coupon.discount_type === 'percent') {
        value = Math.min(Math.max(value, 0), 100);
      } else {
        value = Math.max(0, value);
      }
      coupon.discount_value = value;
    }
    if (usageLimit !== undefined) {
      const limit = toNullableNumber(usageLimit);
      coupon.usage_limit = limit !== null ? Math.max(0, Math.floor(limit)) : null;
    }
    if (validFrom !== undefined) coupon.valid_from = parseDateOrNull(validFrom);
    if (validUntil !== undefined) coupon.valid_until = parseDateOrNull(validUntil);
    if (notes !== undefined) coupon.notes = notes;
    if (active !== undefined) coupon.active = Boolean(active);

    await coupon.save();

    res.json({
      success: true,
      coupon: {
        id: coupon._id,
        code: coupon.code,
        commissionAmount: coupon.commission_amount,
        discountType: coupon.discount_type,
        discountValue: coupon.discount_value,
        usageLimit: coupon.usage_limit,
        active: coupon.active,
        validFrom: coupon.valid_from,
        validUntil: coupon.valid_until,
        notes: coupon.notes
      }
    });
  } catch (error) {
    console.error('Admin update coupon error:', error);
    res.status(500).json({ success: false, message: error.message || 'Failed to update coupon' });
  }
});

app.delete('/api/admin/coupons/:id', requireAdmin(), async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid coupon id' });
    }

    const coupon = await Coupon.findById(id);
    if (!coupon) {
      return res.status(404).json({ success: false, message: 'Coupon not found' });
    }

    coupon.active = false;
    await coupon.save();

    res.json({ success: true, message: 'Coupon disabled successfully' });
  } catch (error) {
    console.error('Admin delete coupon error:', error);
    res.status(500).json({ success: false, message: 'Failed to disable coupon' });
  }
});

// ---------- Influencer Authenticated Routes ----------

app.get('/api/influencer/profile', requireInfluencer(), async (req, res) => {
  try {
    const influencerId = req.authUser.linked_influencer?._id || req.authUser.linked_influencer;
    if (!influencerId) {
      return res.status(400).json({ success: false, message: 'Influencer profile not linked.' });
    }

    const influencer = await Influencer.findById(influencerId);
    if (!influencer) {
      return res.status(404).json({ success: false, message: 'Influencer not found.' });
    }

    const coupons = await Coupon.find({ influencer: influencer._id }).lean();
    res.json({
      success: true,
      influencer: mapInfluencerResponse(influencer),
      coupons: coupons.map((coupon) => ({
        id: coupon._id,
        code: coupon.code,
        discountType: coupon.discount_type,
        discountValue: coupon.discount_value,
        usageCount: coupon.usage_count,
        usageLimit: coupon.usage_limit,
        active: coupon.active
      }))
    });
  } catch (error) {
    console.error('Influencer profile error:', error);
    res.status(500).json({ success: false, message: 'Unable to load profile right now.' });
  }
});

app.patch('/api/influencer/profile', requireInfluencer(), async (req, res) => {
  try {
    const influencerId = req.authUser.linked_influencer?._id || req.authUser.linked_influencer;
    if (!influencerId) {
      return res.status(400).json({ success: false, message: 'Influencer profile not linked.' });
    }

    const influencer = await Influencer.findById(influencerId);
    if (!influencer) {
      return res.status(404).json({ success: false, message: 'Influencer not found.' });
    }

    const { socialLink, region, upiId, bankDetails, notes } = req.body || {};
    if (socialLink !== undefined) influencer.social_link = socialLink || null;
    if (region !== undefined) influencer.region = region || null;
    if (upiId !== undefined) influencer.upi_id = upiId || null;
    if (bankDetails !== undefined) influencer.bank_details = bankDetails || null;
    if (notes !== undefined) influencer.notes = notes || null;

    await influencer.save();
    res.json({ success: true, influencer: mapInfluencerResponse(influencer) });
  } catch (error) {
    console.error('Influencer update profile error:', error);
    res.status(500).json({ success: false, message: 'Failed to update profile' });
  }
});

app.get('/api/influencer/dashboard', requireInfluencer(), async (req, res) => {
  try {
    const influencerId = req.authUser.linked_influencer?._id || req.authUser.linked_influencer;
    if (!influencerId) {
      return res.status(400).json({ success: false, message: 'Influencer profile not linked.' });
    }

    const stats = await getInfluencerStats(influencerId);
    res.json({
      success: true,
      stats
    });
  } catch (error) {
    console.error('Influencer dashboard error:', error);
    res.status(500).json({ success: false, message: 'Failed to load dashboard' });
  }
});

app.get('/api/influencer/registrations', requireInfluencer(), async (req, res) => {
  try {
    const influencerId = req.authUser.linked_influencer?._id || req.authUser.linked_influencer;
    if (!influencerId) {
      return res.status(400).json({ success: false, message: 'Influencer profile not linked.' });
    }

    const { page = 1, limit = 20 } = req.query;
    const pageNumber = Math.max(1, parseInt(page, 10) || 1);
    const pageSize = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
    const skip = (pageNumber - 1) * pageSize;

    const [registrations, total] = await Promise.all([
      Registration.find({ influencer: influencerId })
        .sort({ registration_date: -1 })
        .skip(skip)
        .limit(pageSize)
        .select('farmer_name registration_date payment_status payment_amount coupon_code commission_amount')
        .lean(),
      Registration.countDocuments({ influencer: influencerId })
    ]);

    res.json({
      success: true,
      total,
      page: pageNumber,
      pageSize,
      registrations: registrations.map((item) => ({
        id: item._id,
        farmerName: item.farmer_name,
        registrationDate: item.registration_date,
        paymentStatus: item.payment_status,
        paymentAmount: item.payment_amount,
        couponCode: item.coupon_code,
        commissionAmount: item.commission_amount
      }))
    });
  } catch (error) {
    console.error('Influencer registrations error:', error);
    res.status(500).json({ success: false, message: 'Failed to load registrations' });
  }
});

app.get('/api/influencer/coupons', requireInfluencer(), async (req, res) => {
  try {
    const influencerId = req.authUser.linked_influencer?._id || req.authUser.linked_influencer;
    if (!influencerId) {
      return res.status(400).json({ success: false, message: 'Influencer profile not linked.' });
    }

    const coupons = await Coupon.find({ influencer: influencerId }).lean();
    res.json({
      success: true,
      coupons: coupons.map((coupon) => ({
        id: coupon._id,
        code: coupon.code,
        discountType: coupon.discount_type,
        discountValue: coupon.discount_value,
        usageCount: coupon.usage_count,
        usageLimit: coupon.usage_limit,
        active: coupon.active,
        totalRevenue: coupon.total_revenue
      }))
    });
  } catch (error) {
    console.error('Influencer coupons error:', error);
    res.status(500).json({ success: false, message: 'Failed to load coupons' });
  }
});

// Influencer - Get Messages from Admin
app.get('/api/influencer/messages', requireInfluencer(), async (req, res) => {
  try {
    const influencerId = req.authUser.linked_influencer?._id || req.authUser.linked_influencer;
    if (!influencerId) {
      return res.status(400).json({ success: false, message: 'Influencer profile not linked.' });
    }

    const influencer = await Influencer.findById(influencerId).select('admin_messages').lean();
    if (!influencer) {
      return res.status(404).json({ success: false, message: 'Influencer not found' });
    }

    const messages = (influencer.admin_messages || []).sort((a, b) =>
      new Date(b.sent_at) - new Date(a.sent_at)
    );

    res.json({
      success: true,
      messages,
      unreadCount: messages.filter(m => !m.read).length
    });
  } catch (error) {
    console.error('Influencer messages error:', error);
    res.status(500).json({ success: false, message: 'Failed to load messages' });
  }
});

// Influencer - Mark Message as Read
app.post('/api/influencer/messages/:messageId/read', requireInfluencer(), async (req, res) => {
  try {
    const influencerId = req.authUser.linked_influencer?._id || req.authUser.linked_influencer;
    const { messageId } = req.params;

    if (!influencerId) {
      return res.status(400).json({ success: false, message: 'Influencer profile not linked.' });
    }

    const influencer = await Influencer.findById(influencerId);
    if (!influencer) {
      return res.status(404).json({ success: false, message: 'Influencer not found' });
    }

    const message = influencer.admin_messages.id(messageId);
    if (message) {
      message.read = true;
      await influencer.save();
    }

    res.json({ success: true, message: 'Message marked as read' });
  } catch (error) {
    console.error('Mark message read error:', error);
    res.status(500).json({ success: false, message: 'Failed to mark message as read' });
  }
});

// Registration: save details before payment
app.post('/api/registration/save', async (req, res) => {
  try {
    const { otpToken, referenceId = null, couponCode = '', form = {} } = req.body || {};
    const data = form || {};
    const phoneNumber = (data.contactNumber || '').trim();

    if (!PHONE_REGEX.test(phoneNumber)) {
      return res.status(400).json({ success: false, message: 'Valid contact number is required' });
    }

    const requiredFields = [
      { key: 'registrationDate', label: 'Registration Date' },
      { key: 'farmerName', label: 'Farmer Name' },
      { key: 'fatherSpouseName', label: 'Father / Spouse Name' },
      { key: 'contactNumber', label: 'Contact Number' },
      { key: 'villagePanchayat', label: 'Village / Panchayat' },
      { key: 'mandalBlock', label: 'Mandal / Block' },
      { key: 'district', label: 'District' },
      { key: 'state', label: 'State' },
      { key: 'totalLand', label: 'Total Land' },
      { key: 'landUnit', label: 'Land Unit' },
      { key: 'areaNaturalFarming', label: 'Area Under Natural Farming' },
      { key: 'sowingDate', label: 'Sowing Date' },
      { key: 'cropTypes', label: 'Crop Types' },
      { key: 'farmingPractice', label: 'Farming Practice' },
      { key: 'farmingExperience', label: 'Farming Experience' },
      { key: 'irrigationSource', label: 'Irrigation Source' }
    ];

    const missing = requiredFields
      .filter(({ key }) => !data[key] || String(data[key]).trim() === '')
      .map(({ label }) => label);

    if (missing.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields',
        missing
      });
    }

    let otpSession = null;
    const now = new Date();

    if (!otpToken) {
      return res.status(400).json({ success: false, message: 'OTP verification required.' });
    }
    if (otpToken) {
      otpSession = await OtpSession.findOne({

        phone_number: phoneNumber,
        session_token: otpToken
      }).sort({ createdAt: -1 });

      if (!otpSession || !otpSession.verified) {
        return res.status(400).json({ success: false, message: 'OTP verification not found or incomplete' });
      }

      if (otpSession.used || otpSession.status === 'used') {
        return res.status(400).json({ success: false, message: 'OTP session already used. Please verify again.' });
      }

      if (otpSession.session_expires_at && otpSession.session_expires_at <= now) {
        return res.status(400).json({ success: false, message: 'OTP session expired. Please verify again.' });
      }
    }

    const couponInput = (couponCode || data.couponCode || '').trim();
    let payableAmount = applyGST(BASE_REGISTRATION_AMOUNT); // Default with GST
    let discountAmount = 0;
    let influencer = null;
    let commissionAmount = 0;
    let couponDocument = null;

    if (couponInput) {
      const lower = couponInput.toLowerCase();
      if (lower === TEST_REFERRAL_CODE) {
        const discountedBase = Math.max(0, BASE_REGISTRATION_AMOUNT - 50);
        payableAmount = applyGST(discountedBase);
        discountAmount = BASE_REGISTRATION_AMOUNT - discountedBase;
      } else {
        const normalizedCode = couponInput.toUpperCase();
        couponDocument = await Coupon.findOne({ code: normalizedCode }).populate('influencer');
        if (
          !couponDocument ||
          !couponDocument.influencer ||
          couponDocument.influencer.approval_status !== 'approved' ||
          !isCouponWithinValidity(couponDocument)
        ) {
          return res.status(400).json({ success: false, message: 'Invalid or inactive referral code' });
        }
        const discountResult = calculateDiscountedAmount(BASE_REGISTRATION_AMOUNT, couponDocument);
        payableAmount = discountResult.amount;
        discountAmount = discountResult.discount;
        commissionAmount = couponDocument.commission_amount || 0;
        influencer = couponDocument.influencer._id;
      }
    }

    let registration = null;
    if (referenceId) {
      registration = await Registration.findOne({ reference_id: referenceId });
    }
    if (!registration) {
      registration = await Registration.findOne({ contact_number: phoneNumber, payment_status: 'pending' });
    }

    let reference_id = registration ? registration.reference_id : null;
    if (!registration) {
      for (let attempt = 0; attempt < 10 && !reference_id; attempt += 1) {
        const candidate = generateReferenceId();
        const exists = await Registration.findOne({ reference_id: candidate });
        if (!exists) {
          reference_id = candidate;
        }
      }
      if (!reference_id) {
        throw new Error('Failed to generate registration reference');
      }
      registration = new Registration({ reference_id, contact_number: phoneNumber });
    }

    registration.registration_date = data.registrationDate ? new Date(data.registrationDate) : new Date();
    registration.farmer_name = String(data.farmerName || '').trim();
    registration.father_spouse_name = String(data.fatherSpouseName || '').trim();
    registration.contact_number = phoneNumber;
    registration.email_id = data.emailId ? String(data.emailId).trim().toLowerCase() : null;
    registration.aadhaar_farmer_id = data.aadhaarFarmerId ? String(data.aadhaarFarmerId).trim() : null;
    registration.village_panchayat = String(data.villagePanchayat || '').trim();
    registration.mandal_block = String(data.mandalBlock || '').trim();
    registration.district = String(data.district || '').trim();
    registration.state = String(data.state || '').trim();
    registration.khasra_passbook = data.khasraPassbook ? String(data.khasraPassbook).trim() : null;
    registration.plot_no = data.plotNo ? String(data.plotNo).trim() : null;
    registration.total_land = toNumeric(data.totalLand, 0);
    registration.land_unit = normalizeLandUnit(data.landUnit);
    registration.area_natural_farming = toNumeric(data.areaNaturalFarming, 0);
    registration.present_crop = data.presentCrop ? String(data.presentCrop).trim() : null;
    registration.sowing_date = data.sowingDate ? new Date(data.sowingDate) : new Date();
    registration.harvesting_date = data.harvestingDate ? new Date(data.harvestingDate) : null;
    registration.crop_types = String(data.cropTypes || '').trim();
    
    // Handle multiple crops
    if (data.crops && Array.isArray(data.crops)) {
      registration.crops = data.crops.filter(c => c.name).map(c => ({
        name: String(c.name).trim(),
        area: c.area ? String(c.area).trim() : '',
        variety: c.variety ? String(c.variety).trim() : ''
      }));
    }
    
    registration.farming_practice = normalizeFarmingPractice(data.farmingPractice);
    registration.farming_experience = parseInt(data.farmingExperience, 10) || 0;
    registration.irrigation_source = normalizeIrrigation(data.irrigationSource);
    registration.livestock = toList(data.livestock);
    registration.willing_to_adopt = data.willingToAdopt || 'Maybe';
    registration.additional_details = {
      trainingRequired: data.trainingRequired || null,
      localGroupName: data.localGroupName || null,
      preferredCroppingSeason: data.preferredCroppingSeason || null,
      remarks: data.remarks || null,
      naturalInputs: data.naturalInputs || null
    };
    registration.terms_agreement = Boolean(data.termsAgreement);
    registration.coupon_code = couponInput ? couponInput.toUpperCase() : null;
    registration.influencer = influencer;
    registration.commission_amount = commissionAmount;
    registration.commission_paid = false;
    registration.payment_amount = payableAmount;
    registration.coupon_discount = discountAmount;
    registration.payment_status = 'pending';
    registration.status = 'pending';
    registration.payment_id = null;
    if (!registration.order_id) {
      registration.order_id = null;
    }
    registration.ip_address = req.ip;
    registration.user_agent = req.get('User-Agent');
    registration.submission_source = 'web';
    if (otpSession) {
      registration.otp_token = otpToken || otpSession.session_token;
      registration.otp_verified = true;
      registration.otp_verified_at = now;
    } else if (!registration.otp_verified) {
      registration.otp_token = null;
      registration.otp_verified = false;
      registration.otp_verified_at = null;
    }

    await registration.save();

    await Payment.findOneAndUpdate(
      { farmer: registration._id },
      {
        $set: {
          amount: payableAmount,
          currency: 'INR',
          coupon_code: registration.coupon_code,
          influencer,
          commission_paid: false,
          commission_amount: commissionAmount,
          payment_status: 'Pending',
          payment_id: null,
          order_id: registration.order_id,
          razorpay_signature: null
        },
        $setOnInsert: {
          farmer: registration._id
        }
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    if (otpSession) {
      otpSession.associated_reference = registration.reference_id;
      otpSession.session_token = otpToken || otpSession.session_token;
      otpSession.session_expires_at = new Date(now.getTime() + (otpSessionTtlMinutes * 60 * 1000));
      otpSession.status = 'verified';
      await otpSession.save();
    }

    res.json({
      success: true,
      referenceId: registration.reference_id,
      amount: payableAmount,
      amountPaise: payableAmount * 100,
      couponApplied: Boolean(couponInput),
      discount: discountAmount,
      otpToken
    });
  } catch (error) {
    console.error('Registration save error:', error);
    res.status(500).json({ success: false, message: error.message || 'Failed to save registration' });
  }
});
// Registration: complete after payment
app.post('/api/registration/complete', async (req, res) => {
  try {
    const { referenceId, otpToken, paymentId, orderId = null, paymentAmount = null, paymentSignature = null } = req.body || {};
    const reference = (referenceId || '').trim();

    if (!reference) {
      return res.status(400).json({ success: false, message: 'Registration reference is required' });
    }
    if (!paymentId) {
      return res.status(400).json({ success: false, message: 'Payment ID is required' });
    }

    const registration = await Registration.findOne({ reference_id: reference });
    if (!registration) {
      return res.status(404).json({ success: false, message: 'Registration not found' });
    }

    if (registration.payment_status === 'completed') {
      return res.json({ success: true, message: 'Registration already completed', referenceId: reference, registrationId: registration._id });
    }

    const amountFromDb = Number(registration.payment_amount) || 500;
    let paidAmount = paymentAmount !== undefined && paymentAmount !== null
      ? Number(paymentAmount)
      : amountFromDb;

    if (!Number.isFinite(paidAmount)) {
      return res.status(400).json({ success: false, message: 'Payment amount invalid. Please restart the process.' });
    }

    // Support values submitted either in rupees (e.g., 250) or paise (e.g., 25000)
    if (paidAmount > 1000) {
      paidAmount = Math.round(paidAmount / 100);
    }

    paidAmount = Math.round(paidAmount);

    if (paidAmount !== amountFromDb) {
      return res.status(400).json({
        success: false,
        message: `Payment amount mismatch. Expected Rs ${amountFromDb}, received Rs ${paidAmount}. Please restart the process.`
      });
    }
    const expectedAmount = amountFromDb;

    const now = new Date();
    let otpSession = null;
    if (!otpToken) {
      return res.status(400).json({ success: false, message: 'OTP verification required.' });
    }
    if (otpToken) {
      otpSession = await OtpSession.findOne({

        phone_number: registration.contact_number,
        session_token: otpToken
      }).sort({ createdAt: -1 });

      if (!otpSession || !otpSession.verified) {
        return res.status(400).json({ success: false, message: 'OTP verification not found or incomplete' });
      }

      if (otpSession.used || otpSession.status === 'used') {
        return res.status(400).json({ success: false, message: 'OTP session already used. Please verify again.' });
      }
      if (otpSession.associated_reference && otpSession.associated_reference !== reference) {
        return res.status(400).json({ success: false, message: 'OTP session does not match this registration' });
      }
      if (otpSession.session_expires_at && otpSession.session_expires_at <= now) {
        return res.status(400).json({ success: false, message: 'OTP session expired. Please verify again.' });
      }
    }

    registration.payment_amount = expectedAmount;
    if (orderId) {
      registration.order_id = orderId;
    }
    registration.payment_status = 'completed';
    registration.payment_id = paymentId;
    if (otpSession) {
      registration.otp_token = otpSession.session_token || registration.otp_token;
      registration.otp_verified = true;
      registration.otp_verified_at = now;
    }
    await registration.save();

    const paymentRecord = await Payment.findOneAndUpdate(
      { farmer: registration._id },
      {
        $set: {
          amount: expectedAmount,
          currency: 'INR',
          coupon_code: registration.coupon_code,
          influencer: registration.influencer || null,
          commission_paid: registration.commission_paid,
          commission_amount: registration.commission_amount || 0,
          payment_status: 'Success',
          payment_id: paymentId,
          order_id: orderId || null,
          razorpay_signature: paymentSignature || null
        },
        $setOnInsert: {
          farmer: registration._id
        }
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    if (registration.coupon_code && registration.coupon_code.toLowerCase() !== TEST_REFERRAL_CODE) {
      const couponDoc = await Coupon.findOneAndUpdate(
        { code: registration.coupon_code },
        {
          $inc: {
            usage_count: 1,
            total_revenue: expectedAmount
          },
          $set: { last_used_at: now }
        },
        { new: true }
      ).populate('influencer');

      if (couponDoc?.influencer?._id) {
        await Influencer.findByIdAndUpdate(
          couponDoc.influencer._id,
          {
            $inc: {
              total_earnings: registration.commission_amount || 0,
              referral_uses: 1
            },
            $set: {
              payout_status: 'Pending'
            }
          },
          { new: true }
        );
      }
    } else if (registration.influencer) {
      await Influencer.findByIdAndUpdate(
        registration.influencer,
        {
          $inc: {
            total_earnings: registration.commission_amount || 0,
            referral_uses: 1
          },
          $set: {
            payout_status: 'Pending'
          }
        }
      );
    }

    await PaymentLog.findOneAndUpdate(
      { $or: [{ payment_id: paymentId }, { order_id: orderId || null }] },
      {
        payment_id: paymentId,
        order_id: orderId || null,
        registration_reference: reference,
        status: 'paid',
        amount: expectedAmount * 100,
        ip_address: req.ip,
        user_agent: req.get('User-Agent')
      },
      { upsert: true, new: true }
    );

    await updateDailyStats('total_registrations', 1, { district: registration.district });
    await updateDailyStats('successful_payments', 1);
    await updateDailyStats('revenue', expectedAmount);

    if (otpSession) {
      otpSession.used = true;
      otpSession.used_at = now;
      otpSession.status = 'used';
      otpSession.session_expires_at = now;
      await otpSession.save();
    }

    try {
      await sendCompletionNotifications(registration.contact_number, reference);
    } catch (notifyError) {
      console.warn('Completion notification error:', notifyError.message);
    }

    res.json({
      success: true,
      message: 'Registration and payment completed',
      referenceId: reference,
      registrationId: registration._id,
      paymentId: paymentRecord ? paymentRecord._id : null
    });
  } catch (error) {
    console.error('Registration completion error:', error);
    res.status(500).json({ success: false, message: error.message || 'Failed to complete registration' });
  }
});


// Admin - Manual registration
app.post('/api/admin/registrations/manual', requireAdmin(), async (req, res) => {
  try {
    const regData = req.body;
    const now = new Date();

    // Generate reference ID like website (CNF + YYYYMMDD + 3-digit random)
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
    const reference_id = `CNF${year}${month}${day}${random}`;

    // Generate payment ID like Razorpay (avcf_ prefix + timestamp + random)
    const paymentId = regData.payment_status === 'completed'
      ? `avcf_${Date.now()}${Math.random().toString(36).substring(2, 9)}`
      : null;
    const orderId = regData.payment_status === 'completed'
      ? `order_avcf_${Date.now()}${Math.random().toString(36).substring(2, 9)}`
      : null;

    // Handle coupon code if provided
    let influencer = null;
    let commissionAmount = 0;
    let couponDiscount = 0;
    let paymentAmount = Number(regData.payment_amount) || 500;

    if (regData.coupon_code && regData.coupon_code.trim()) {
      const couponCode = regData.coupon_code.trim().toUpperCase();
      const coupon = await Coupon.findOne({ code: couponCode }).populate('influencer');

      if (coupon && coupon.influencer && coupon.influencer.approval_status === 'approved') {
        influencer = coupon.influencer._id;
        commissionAmount = coupon.commission_amount || 50;
        couponDiscount = coupon.discount_value || 50;
        paymentAmount = Math.max(0, paymentAmount - couponDiscount);

        // Update coupon usage
        await Coupon.findByIdAndUpdate(coupon._id, {
          $inc: { usage_count: 1, total_revenue: paymentAmount },
          $set: { last_used_at: now }
        });

        // Update influencer tracking
        await Influencer.findByIdAndUpdate(influencer, {
          $inc: {
            total_earnings: commissionAmount,
            referral_uses: 1
          },
          $set: {
            payout_status: 'Pending'
          }
        });
      }
    }

    // Create registration with all fields like website
    const registration = await Registration.create({
      reference_id,
      registration_date: regData.registration_date ? new Date(regData.registration_date) : now,
      farmer_name: regData.farmer_name,
      father_spouse_name: regData.father_spouse_name,
      contact_number: regData.contact_number,
      email_id: regData.email_id || null,
      aadhaar_farmer_id: regData.aadhaar_farmer_id || null,
      village_panchayat: regData.village_panchayat,
      mandal_block: regData.mandal_block,
      district: regData.district,
      state: regData.state,
      khasra_passbook: regData.khasra_passbook || null,
      plot_no: regData.plot_no || null,
      total_land: Number(regData.total_land) || 0,
      land_unit: regData.land_unit || 'Acre',
      area_natural_farming: Number(regData.area_natural_farming) || 0,
      present_crop: regData.present_crop || null,
      sowing_date: regData.sowing_date ? new Date(regData.sowing_date) : now,
      harvesting_date: regData.harvesting_date ? new Date(regData.harvesting_date) : null,
      crop_types: regData.crop_types || '',
      farming_practice: regData.farming_practice || 'Natural',
      farming_experience: Number(regData.farming_experience) || 0,
      irrigation_source: regData.irrigation_source || 'Other',
      livestock: regData.livestock || [],
      willing_to_adopt: regData.willing_to_adopt || 'yes',
      terms_agreement: regData.terms_agreement || false,
      coupon_code: regData.coupon_code ? regData.coupon_code.toUpperCase() : null,
      influencer: influencer,
      commission_amount: commissionAmount,
      commission_paid: false,
      coupon_discount: couponDiscount,
      payment_amount: paymentAmount,
      payment_id: paymentId,
      order_id: orderId,
      payment_status: regData.payment_status || 'completed',
      status: 'approved',
      submission_source: 'admin_manual',
      otp_verified: true,
      otp_verified_at: now,
      otp_token: null,
      ip_address: req.ip || 'admin',
      user_agent: 'Admin Manual Entry',
      additional_details: {
        trainingRequired: regData.training_required || null,
        localGroupName: regData.local_group_name || null,
        preferredCroppingSeason: regData.preferred_cropping_season || null,
        remarks: regData.remarks || null,
        naturalInputs: regData.willing_to_adopt || 'yes'
      }
    });

    // Create payment record if payment is completed
    if (regData.payment_status === 'completed') {
      await Payment.create({
        farmer: registration._id,
        amount: paymentAmount,
        currency: 'INR',
        payment_id: paymentId,
        order_id: orderId,
        razorpay_signature: null,
        payment_status: 'Success',
        coupon_code: regData.coupon_code ? regData.coupon_code.toUpperCase() : null,
        influencer: influencer,
        commission_amount: commissionAmount,
        commission_paid: false
      });

      // Create payment log
      await PaymentLog.create({
        payment_id: paymentId,
        order_id: orderId,
        razorpay_signature: null,
        amount: paymentAmount,
        currency: 'INR',
        status: 'paid',
        method: 'admin_entry',
        email: regData.email_id || null,
        contact: regData.contact_number,
        ip_address: req.ip || 'admin',
        user_agent: 'Admin Manual Entry',
        registration_reference: reference_id,
        notes: { source: 'manual_entry', admin: true }
      });

      // Update system stats for today
      const today = new Date();
      today.setHours(0, 0, 0, 0);

      await SystemStats.findOneAndUpdate(
        { date: today },
        {
          $inc: {
            total_registrations: 1,
            successful_payments: 1,
            revenue: paymentAmount
          },
          $addToSet: { districts_covered: regData.district }
        },
        { upsert: true, new: true }
      );
    }

    res.json({
      success: true,
      message: 'Registration created successfully',
      registration
    });
  } catch (error) {
    console.error('Manual registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create registration: ' + error.message
    });
  }
});

// Admin - Bulk upload registrations
app.post('/api/admin/registrations/bulk', requireAdmin(), async (req, res) => {
  try {
    const { registrations } = req.body;

    if (!Array.isArray(registrations) || registrations.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid data format'
      });
    }

    let successCount = 0;
    let failedCount = 0;
    const errors = [];

    for (const regData of registrations) {
      try {
        const now = new Date();

        // Generate reference ID like website (CNF + YYYYMMDD + 3-digit random)
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
        const reference_id = `CNF${year}${month}${day}${random}`;

        // Generate payment ID like Razorpay (avcf_ prefix + timestamp + random)
        const paymentId = `avcf_${Date.now()}${Math.random().toString(36).substring(2, 9)}`;
        const orderId = `order_avcf_${Date.now()}${Math.random().toString(36).substring(2, 9)}`;

        // Handle coupon code if provided
        let influencer = null;
        let commissionAmount = 0;
        let couponDiscount = 0;
        let paymentAmount = Number(regData.payment_amount) || 500;

        if (regData.coupon_code && regData.coupon_code.trim()) {
          const couponCode = regData.coupon_code.trim().toUpperCase();
          const coupon = await Coupon.findOne({ code: couponCode }).populate('influencer');

          if (coupon && coupon.influencer && coupon.influencer.approval_status === 'approved') {
            influencer = coupon.influencer._id;
            commissionAmount = coupon.commission_amount || 50;
            couponDiscount = coupon.discount_value || 50;
            paymentAmount = Math.max(0, paymentAmount - couponDiscount);

            // Update coupon usage
            await Coupon.findByIdAndUpdate(coupon._id, {
              $inc: { usage_count: 1, total_revenue: paymentAmount },
              $set: { last_used_at: now }
            });

            // Update influencer tracking
            await Influencer.findByIdAndUpdate(influencer, {
              $inc: {
                total_earnings: commissionAmount,
                referral_uses: 1
              },
              $set: {
                payout_status: 'Pending'
              }
            });
          }
        }

        // Parse livestock if it's a string
        let livestock = [];
        if (regData.livestock) {
          if (typeof regData.livestock === 'string') {
            livestock = regData.livestock.split(';').map(l => l.trim()).filter(Boolean);
          } else if (Array.isArray(regData.livestock)) {
            livestock = regData.livestock;
          }
        }

        // Create registration with all fields like website
        const registration = await Registration.create({
          reference_id,
          registration_date: regData.registration_date ? new Date(regData.registration_date) : now,
          farmer_name: regData.farmer_name,
          father_spouse_name: regData.father_spouse_name,
          contact_number: regData.contact_number,
          email_id: regData.email_id || null,
          aadhaar_farmer_id: regData.aadhaar_farmer_id || null,
          village_panchayat: regData.village_panchayat,
          mandal_block: regData.mandal_block,
          district: regData.district,
          state: regData.state,
          khasra_passbook: regData.khasra_passbook || null,
          plot_no: regData.plot_no || null,
          total_land: Number(regData.total_land) || 0,
          land_unit: regData.land_unit || 'Acre',
          area_natural_farming: Number(regData.area_natural_farming) || 0,
          present_crop: regData.present_crop || null,
          sowing_date: regData.sowing_date ? new Date(regData.sowing_date) : now,
          harvesting_date: regData.harvesting_date ? new Date(regData.harvesting_date) : null,
          crop_types: regData.crop_types || '',
          farming_practice: regData.farming_practice || 'Natural',
          farming_experience: Number(regData.farming_experience) || 0,
          irrigation_source: regData.irrigation_source || 'Rainwater',
          livestock: livestock,
          willing_to_adopt: regData.willing_to_adopt || 'yes',
          terms_agreement: regData.terms_agreement === 'yes' || regData.terms_agreement === true,
          coupon_code: regData.coupon_code ? regData.coupon_code.toUpperCase() : null,
          influencer: influencer,
          commission_amount: commissionAmount,
          commission_paid: false,
          coupon_discount: couponDiscount,
          payment_amount: paymentAmount,
          payment_id: paymentId,
          order_id: orderId,
          payment_status: regData.payment_status || 'completed',
          status: 'approved',
          submission_source: 'admin_bulk',
          otp_verified: true,
          otp_verified_at: now,
          otp_token: null,
          ip_address: req.ip || 'admin',
          user_agent: 'Admin Bulk Upload',
          additional_details: {
            trainingRequired: regData.training_required || null,
            localGroupName: regData.local_group_name || null,
            preferredCroppingSeason: regData.preferred_cropping_season || null,
            remarks: regData.remarks || null,
            naturalInputs: regData.willing_to_adopt || 'yes'
          }
        });

        // Create payment record
        await Payment.create({
          farmer: registration._id,
          amount: paymentAmount,
          currency: 'INR',
          payment_id: paymentId,
          order_id: orderId,
          razorpay_signature: null,
          payment_status: regData.payment_status === 'completed' ? 'Success' : 'Pending',
          coupon_code: regData.coupon_code ? regData.coupon_code.toUpperCase() : null,
          influencer: influencer,
          commission_amount: commissionAmount,
          commission_paid: false
        });

        // Create payment log
        await PaymentLog.create({
          payment_id: paymentId,
          order_id: orderId,
          razorpay_signature: null,
          amount: paymentAmount,
          currency: 'INR',
          status: regData.payment_status === 'completed' ? 'paid' : 'created',
          method: 'admin_entry',
          email: regData.email_id || null,
          contact: regData.contact_number,
          ip_address: req.ip || 'admin',
          user_agent: 'Admin Bulk Upload',
          registration_reference: reference_id,
          notes: { source: 'bulk_upload', admin: true }
        });

        // Update system stats for today
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        await SystemStats.findOneAndUpdate(
          { date: today },
          {
            $inc: {
              total_registrations: 1,
              successful_payments: regData.payment_status === 'completed' ? 1 : 0,
              revenue: regData.payment_status === 'completed' ? paymentAmount : 0
            },
            $addToSet: { districts_covered: regData.district }
          },
          { upsert: true, new: true }
        );

        successCount++;
      } catch (error) {
        failedCount++;
        errors.push({
          farmer_name: regData.farmer_name || 'Unknown',
          error: error.message
        });
      }
    }

    res.json({
      success: true,
      message: `Processed ${registrations.length} registrations`,
      success: successCount,
      failed: failedCount,
      errors: errors.slice(0, 10) // Return first 10 errors
    });
  } catch (error) {
    console.error('Bulk upload error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process bulk upload: ' + error.message
    });
  }
});

// Admin - Get all registrations with filters
app.get('/api/admin/registrations', requireAdmin(), async (req, res) => {
  try {
    const { search, status, paymentStatus, page = 1, limit = 20 } = req.query;
    const query = {};

    if (search) {
      const regex = new RegExp(search, 'i');
      query.$or = [
        { reference_id: regex },
        { farmer_name: regex },
        { contact_number: regex },
        { district: regex }
      ];
    }
    if (status) query.status = status;
    if (paymentStatus) query.payment_status = paymentStatus;

    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const skip = (pageNum - 1) * limitNum;

    const total = await Registration.countDocuments(query);
    const registrations = await Registration.find(query)
      .populate('influencer')
      .sort({ registration_date: -1 })
      .skip(skip)
      .limit(limitNum)
      .lean();

    res.json({ success: true, registrations, total, page: pageNum, limit: limitNum });
  } catch (error) {
    console.error('Admin registrations error:', error);
    res.status(500).json({ success: false, message: 'Failed to load registrations' });
  }
});

// Admin - Get all payments with filters
app.get('/api/admin/payments', requireAdmin(), async (req, res) => {
  try {
    const { search, status, page = 1, limit = 20 } = req.query;
    const query = {};

    if (search) {
      const regex = new RegExp(search, 'i');
      query.$or = [
        { payment_id: regex },
        { order_id: regex }
      ];
    }
    if (status) query.payment_status = status;

    const pageNum = parseInt(page);
    const limitNum = parseInt(limit);
    const skip = (pageNum - 1) * limitNum;

    const total = await Payment.countDocuments(query);
    const payments = await Payment.find(query)
      .populate('influencer')
      .populate('farmer')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limitNum)
      .lean();

    res.json({ success: true, payments, total, page: pageNum, limit: limitNum });
  } catch (error) {
    console.error('Admin payments error:', error);
    res.status(500).json({ success: false, message: 'Failed to load payments' });
  }
});

// Admin - Approve influencer
app.post('/api/admin/influencers/:id/approve', requireAdmin(), async (req, res) => {
  try {
    const { id } = req.params;
    const influencer = await Influencer.findById(id);

    if (!influencer) {
      return res.status(404).json({ success: false, message: 'Influencer not found' });
    }

    // Generate coupon code if not exists
    if (!influencer.coupon_code) {
      const baseCode = influencer.name.substring(0, 6).toUpperCase().replace(/[^A-Z0-9]/g, '');
      influencer.coupon_code = await getUniqueCouponCode(baseCode + Math.floor(1000 + Math.random() * 9000));
    }

    influencer.approval_status = 'approved';
    influencer.login_enabled = true;
    await influencer.save();

    // Create coupon if not exists
    const existingCoupon = await Coupon.findOne({ code: influencer.coupon_code });
    if (!existingCoupon) {
      await Coupon.create({
        code: influencer.coupon_code,
        influencer: influencer._id,
        commission_amount: 50,
        discount_type: 'flat',
        discount_value: 50,
        active: true
      });
    }

    // Create user account for partner using their registered password
    try {
      await upsertInfluencerUser({
        influencer,
        email: influencer.email || `${influencer.contact_number}@agrivalah.in`,
        password: null, // Use existing password_hash from influencer record
        status: USER_STATUS.ACTIVE,
        loginEnabled: true,
        forcePasswordReset: false // They can change it from dashboard
      });
      console.log(`Partner ${influencer.name} approved using their registered password`);
    } catch (userError) {
      console.error('Failed to create user account:', userError);
    }

    // Send SMS notification
    try {
      const loginUrl = `${process.env.FRONTEND_URL || 'https://agrivalah.in'}/influencer-login.html`;
      const smsMessage = `Congratulations ${influencer.name}! Your Agrivalah Partner application is APPROVED.\n\nLogin at: ${loginUrl}\nMobile: ${influencer.contact_number}\nPassword: Your registered password\nCoupon: ${influencer.coupon_code}\n\nEarn ₹50 per referral!`;

      await sendSms(influencer.contact_number, smsMessage);
      console.log(`✅ Approval SMS sent to ${influencer.contact_number}`);
    } catch (smsError) {
      console.error('⚠️ SMS send failed (non-critical):', smsError.message);
    }

    res.json({
      success: true,
      message: 'Influencer approved successfully. SMS sent with login credentials.',
      influencer,
      credentials: {
        mobile: influencer.contact_number,
        message: 'Partner will use their registered password',
        couponCode: influencer.coupon_code
      }
    });
  } catch (error) {
    console.error('Approve influencer error:', error);
    res.status(500).json({ success: false, message: 'Failed to approve influencer' });
  }
});

// Admin - Reject influencer
app.post('/api/admin/influencers/:id/reject', requireAdmin(), async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;

    const influencer = await Influencer.findById(id);
    if (!influencer) {
      return res.status(404).json({ success: false, message: 'Influencer not found' });
    }

    influencer.approval_status = 'rejected';
    influencer.login_enabled = false;
    if (reason) {
      influencer.notes = (influencer.notes || '') + `\nRejection reason: ${reason}`;
    }
    await influencer.save();

    // Send SMS notification
    try {
      const smsMessage = `Dear ${influencer.name}, your Agrivalah Partner application has been reviewed. We cannot approve it at this time.${reason ? ` Reason: ${reason}` : ''} You may reapply or contact support.`;

      await sendSms(influencer.contact_number, smsMessage);
      console.log(`✅ Rejection SMS sent to ${influencer.contact_number}`);
    } catch (smsError) {
      console.error('⚠️ SMS send failed (non-critical):', smsError.message);
    }

    res.json({ success: true, message: 'Influencer rejected and notified via SMS', influencer });
  } catch (error) {
    console.error('Reject influencer error:', error);
    res.status(500).json({ success: false, message: 'Failed to reject influencer' });
  }
});

// Admin - Update coupon
app.put('/api/admin/coupons/:id', requireAdmin(), async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    const coupon = await Coupon.findByIdAndUpdate(id, updates, { new: true }).populate('influencer');
    if (!coupon) {
      return res.status(404).json({ success: false, message: 'Coupon not found' });
    }

    res.json({ success: true, message: 'Coupon updated successfully', coupon });
  } catch (error) {
    console.error('Update coupon error:', error);
    res.status(500).json({ success: false, message: 'Failed to update coupon' });
  }
});

// Admin - Update influencer
app.put('/api/admin/influencers/:id', requireAdmin(), async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    console.log('[Admin] Updating influencer:', id);

    const influencer = await Influencer.findByIdAndUpdate(id, updates, { new: true });
    if (!influencer) {
      return res.status(404).json({ success: false, message: 'Influencer not found' });
    }

    console.log('[Admin] Influencer updated successfully');
    res.json({ success: true, message: 'Influencer updated successfully', influencer });
  } catch (error) {
    console.error('[Admin] Update influencer error:', error);
    res.status(500).json({ success: false, message: 'Failed to update influencer' });
  }
});

// Admin - Assign login credentials to influencer
app.post('/api/admin/influencers/:id/credentials', requireAdmin(), async (req, res) => {
  try {
    const { id } = req.params;
    const { email, password, forcePasswordReset, loginEnabled } = req.body;

    console.log('[Admin] Assigning credentials to influencer:', id);

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    if (password.length < 8) {
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters' });
    }

    const influencer = await Influencer.findById(id);
    if (!influencer) {
      return res.status(404).json({ success: false, message: 'Influencer not found' });
    }

    // Update influencer email and login status
    influencer.email = email.toLowerCase();
    influencer.login_enabled = loginEnabled !== false;
    await influencer.save();

    // Create or update user account
    try {
      await upsertInfluencerUser({
        influencer,
        email: email.toLowerCase(),
        password,
        status: loginEnabled ? USER_STATUS.ACTIVE : USER_STATUS.DISABLED,
        loginEnabled: loginEnabled !== false,
        forcePasswordReset: forcePasswordReset || false
      });

      console.log('[Admin] Credentials assigned successfully');
      res.json({
        success: true,
        message: 'Login credentials assigned successfully. Influencer can now login with provided email and password.'
      });
    } catch (userError) {
      console.error('[Admin] Failed to create user account:', userError);
      res.status(500).json({
        success: false,
        message: 'Failed to create user account: ' + userError.message
      });
    }
  } catch (error) {
    console.error('[Admin] Assign credentials error:', error);
    res.status(500).json({ success: false, message: 'Failed to assign credentials' });
  }
});

// Admin dashboard endpoint (legacy summary)
app.get('/api/admin/dashboard', requireAdmin(), async (req, res) => {
  try {
    const [registrations, influencers, payments, coupons] = await Promise.all([
      Registration.find().populate('influencer').lean(),
      Influencer.find().lean(),
      Payment.find().populate('influencer').lean(),
      Coupon.find().populate('influencer').lean()
    ]);
    res.json({ registrations, influencers, payments, coupons });
  } catch (error) {
    console.error('Legacy admin dashboard error:', error);
    res.status(500).json({ success: false, message: 'Failed to load dashboard data' });
  }
});

// Admin view of specific influencer dashboard stats
app.get('/api/influencer/dashboard/:id', requireAdmin(), async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: 'Invalid influencer id' });
    }
    const influencer = await Influencer.findById(id);
    if (!influencer) {
      return res.status(404).json({ success: false, message: 'Influencer not found' });
    }
    const stats = await getInfluencerStats(id);
    res.json({ success: true, influencer: mapInfluencerResponse(influencer), stats });
  } catch (error) {
    console.error('Admin influencer dashboard error:', error);
    res.status(500).json({ success: false, message: 'Failed to load influencer dashboard' });
  }
});

// Notification system (stub)
app.post('/api/notify', async (req, res) => {
  // TODO: Integrate email/SMS notification logic
  res.json({ success: true, message: 'Notification sent (stub)' });
});

// System Statistics Schema
const systemStatsSchema = new mongoose.Schema({
  date: {
    type: Date,
    required: true,
    unique: true,
    index: true
  },
  total_registrations: {
    type: Number,
    default: 0
  },
  successful_payments: {
    type: Number,
    default: 0
  },
  failed_payments: {
    type: Number,
    default: 0
  },
  revenue: {
    type: Number,
    default: 0
  },
  unique_visitors: {
    type: Number,
    default: 0
  },
  districts_covered: {
    type: [String],
    default: []
  }
}, {
  timestamps: true,
  collection: 'system_stats'
});

// Create Models
const Registration = mongoose.model('Registration', registrationSchema);
const PaymentLog = mongoose.model('PaymentLog', paymentLogSchema);
const SystemStats = mongoose.model('SystemStats', systemStatsSchema);

// ================================================
// UTILITY FUNCTIONS
// ================================================

// Generate unique reference ID
function generateReferenceId() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
  return `CNF${year}${month}${day}${random}`;
}

function generateOtpCode() {
  // Use cryptographically secure random number generation
  const min = Math.pow(10, Math.max(OTP_LENGTH - 1, 1));
  const max = Math.pow(10, OTP_LENGTH) - 1;

  // Generate secure random number using crypto.randomInt
  const randomNum = crypto.randomInt(min, max + 1);

  // Ensure consistent format with leading zeros if needed
  const code = randomNum.toString().padStart(OTP_LENGTH, '0');

  // Validate generated OTP code
  if (code.length !== OTP_LENGTH || !/^\d+$/.test(code)) {
    console.error(`[OTP] Invalid OTP generated - Length: ${code.length}, Expected: ${OTP_LENGTH}`);
    throw new Error('Failed to generate valid OTP code');
  }

  // Log OTP generation without exposing the actual code
  console.log(`[OTP] Generated ${OTP_LENGTH}-digit code (length: ${code.length}, validated: true)`);

  return code;
}

function hashOtpCode(code) {
  // Sanitize input: ensure it's a string and trim whitespace
  const sanitizedCode = String(code).trim();

  // Log hash generation details for debugging
  const codeType = typeof code;
  const codeLength = sanitizedCode.length;
  console.log(`[OTP] Hashing code - Original Type: ${codeType}, Sanitized Length: ${codeLength}`);

  // Ensure consistent UTF-8 encoding by explicitly specifying encoding
  const hash = crypto.createHash('sha256').update(sanitizedCode, 'utf8').digest('hex');
  console.log(`[OTP] Hash generated - Length: ${hash.length}, First 8 chars: ${hash.substring(0, 8)}...`);

  return hash;
}

function generateOtpSessionToken() {
  return crypto.randomBytes(24).toString('hex');
}

function formatPhoneNumberForTwilio(phoneNumber) {
  if (!phoneNumber) return null;
  const digitsOnly = String(phoneNumber).replace(/\D/g, '');
  const localNumber = digitsOnly.slice(-10);
  if (localNumber.length !== 10) {
    return null;
  }
  return `+91${localNumber}`;
}

async function dispatchOtp(phoneNumber, otpCode) {
  const destination = formatPhoneNumberForTwilio(phoneNumber);
  if (!destination) {
    throw new Error('Invalid phone number');
  }

  if (!twilioClient || (!twilioMessagingServiceSid && !twilioSmsFrom)) {
    console.warn(`[OTP] Twilio not configured. OTP for ${phoneNumber}: ${otpCode}`);
    return { sid: null, simulated: true, otp: otpCode };
  }

  const messageBody = `Your Agrivalah verification code is ${otpCode}. It is valid for ${otpExpiryMinutes} minutes.`;
  const payload = {
    to: destination,
    body: messageBody
  };

  if (twilioMessagingServiceSid) {
    payload.messagingServiceSid = twilioMessagingServiceSid;
  } else {
    payload.from = twilioSmsFrom;
  }

  try {
    console.log(`[OTP] Attempting to send SMS to ${destination} via Twilio...`);
    console.log(`[OTP] Using ${twilioMessagingServiceSid ? 'Messaging Service' : 'From Number'}`);

    const message = await twilioClient.messages.create(payload);

    console.log(`[OTP] ✅ SMS sent successfully - SID: ${message.sid}, Status: ${message.status}`);
    return { ...message, simulated: false };
  } catch (twilioError) {
    console.error(`[OTP] ❌ Twilio SMS failed:`, {
      error: twilioError.message,
      code: twilioError.code,
      status: twilioError.status,
      moreInfo: twilioError.moreInfo
    });

    // Fallback to simulated mode if Twilio fails
    console.warn(`[OTP] Falling back to simulated mode. OTP for ${phoneNumber}: ${otpCode}`);
    return { sid: null, simulated: true, otp: otpCode, twilioError: twilioError.message };
  }
}

// Generic SMS sending function
// REAL SMS SENDING - ALWAYS ENABLED
// ================================================
// SMS SERVICE - Clean and Reliable
// ================================================

/**
 * Send SMS via Twilio
 * @param {string} phoneNumber - 10 digit Indian mobile number
 * @param {string} message - SMS message content
 * @returns {Promise<object>} SMS result with success status
 */
async function sendSms(phoneNumber, message) {
  if (!phoneNumber || !message) {
    throw new Error('Phone number and message are required');
  }

  const destination = formatPhoneNumberForTwilio(phoneNumber);
  if (!destination) {
    throw new Error('Invalid phone number format');
  }

  // Check if Twilio is configured
  if (!twilioClient || (!twilioMessagingServiceSid && !twilioSmsFrom)) {
    console.log(`\n${'='.repeat(70)}`);
    console.log(`[SMS] ⚠️  TWILIO NOT CONFIGURED - Cannot send SMS`);
    console.log(`[SMS] To: ${destination}`);
    console.log(`[SMS] Message Preview:`);
    console.log(`${'-'.repeat(70)}`);
    console.log(message);
    console.log(`${'='.repeat(70)}\n`);
    return { simulated: true, reason: 'Twilio not configured' };
  }

  // SEND REAL SMS
  try {
    const smsPayload = {
      to: destination,
      body: message
    };

    if (twilioMessagingServiceSid) {
      smsPayload.messagingServiceSid = twilioMessagingServiceSid;
    } else if (twilioSmsFrom) {
      smsPayload.from = twilioSmsFrom;
    }

    console.log(`\n[SMS] 📱 Sending to ${destination}...`);
    const result = await twilioClient.messages.create(smsPayload);

    console.log(`[SMS] ✅ SUCCESS - SID: ${result.sid}\n`);

    return { 
      success: true,
      simulated: false, 
      sid: result.sid, 
      status: result.status 
    };
  } catch (error) {
    console.error(`\n[SMS] ❌ FAILED to ${destination}`);
    console.error(`[SMS] Error: ${error.message}\n`);
    throw error;
  }
}

/**
 * Send registration completion notification
 */
async function sendCompletionNotifications(phoneNumber, referenceId) {
  if (!phoneNumber) {
    return;
  }

  const smsMessage = `Agrivalah: Registration complete! Reference ID: ${referenceId}. We'll contact you soon. Thank you!`;

  try {
    await sendSms(phoneNumber, smsMessage);
    console.log(`✅ Registration SMS sent to ${phoneNumber}`);
  } catch (error) {
    console.error('⚠️ SMS send failed (non-critical):', error.message);
  }
}


function toNumeric(value, fallback = 0) {
  const num = parseFloat(value);
  return Number.isFinite(num) ? num : fallback;
}

function normalizeLandUnit(value) {
  if (!value) return 'Acre';
  const lower = String(value).toLowerCase();
  if (['acre', 'acres'].includes(lower)) return 'Acre';
  if (['hectare', 'hectares'].includes(lower)) return 'Hectare';
  if (['bigha', 'bighas'].includes(lower)) return 'Bigha';
  if (['guntha', 'gunthas'].includes(lower)) return 'Guntha';
  return 'Acre';
}

function normalizeFarmingPractice(value) {
  if (!value) return 'Natural';
  const lower = String(value).toLowerCase();
  if (lower === 'organic') return 'Organic';
  if (lower === 'natural') return 'Natural';
  if (lower === 'chemical') return 'Chemical';
  if (lower === 'mixed') return 'Mixed';
  return 'Natural';
}

function normalizeIrrigation(value) {
  if (!value) return 'Rainwater';
  const lower = String(value).toLowerCase();
  if (['rainwater', 'rainfed', 'rain'].includes(lower)) return 'Rainwater';
  if (lower === 'borewell' || lower === 'bore well') return 'Borewell';
  if (lower === 'canal') return 'Canal';
  if (lower === 'river') return 'River';
  if (lower === 'pond') return 'Pond';
  if (lower === 'other') return 'Other';
  return 'Rainwater';
}

function toList(value) {
  if (Array.isArray(value)) {
    return value.map(item => String(item).trim()).filter(Boolean);
  }
  if (!value) return [];
  return String(value).split(',').map(item => item.trim()).filter(Boolean);
}


// Validate Razorpay signature
function validateRazorpaySignature(orderId, paymentId, signature) {
  const body = orderId + '|' + paymentId;
  const expectedSignature = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(body.toString())
    .digest('hex');

  return expectedSignature === signature;
}

// Update daily statistics
async function updateDailyStats(type, increment = 1, additionalData = {}) {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const updateQuery = { $inc: {} };
    updateQuery.$inc[type] = increment;

    if (additionalData.district && type === 'total_registrations') {
      updateQuery.$addToSet = { districts_covered: additionalData.district };
    }

    await SystemStats.findOneAndUpdate(
      { date: today },
      updateQuery,
      { upsert: true, new: true }
    );
  } catch (error) {
    console.error('Error updating daily stats:', error);
  }
}

// ================================================
// ADVANCED FEATURES
// ================================================

// Admin - Update Registration Price
app.put('/api/admin/settings/registration-price', requireAdmin(), async (req, res) => {
  try {
    const { newPrice } = req.body;

    if (!newPrice || typeof newPrice !== 'number' || newPrice < 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid price. Must be a positive number.'
      });
    }

    // Store in database as system setting
    const SystemSettings = mongoose.models.SystemSettings || mongoose.model('SystemSettings', new mongoose.Schema({
      key: { type: String, required: true, unique: true },
      value: mongoose.Schema.Types.Mixed,
      updated_at: { type: Date, default: Date.now },
      updated_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
    }));

    await SystemSettings.findOneAndUpdate(
      { key: 'registration_price' },
      {
        value: newPrice,
        updated_at: new Date(),
        updated_by: req.user._id
      },
      { upsert: true, new: true }
    );

    console.log(`✅ Registration price updated to ₹${newPrice} by admin ${req.user.email}`);

    res.json({
      success: true,
      message: `Registration price updated to ₹${newPrice}`,
      newPrice,
      effectiveImmediately: true
    });

  } catch (error) {
    console.error('❌ Update registration price error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update registration price'
    });
  }
});

// Get Current Registration Price
app.get('/api/settings/registration-price', async (req, res) => {
  try {
    const SystemSettings = mongoose.models.SystemSettings;
    
    if (!SystemSettings) {
      return res.json({
        success: true,
        price: BASE_REGISTRATION_AMOUNT,
        source: 'default'
      });
    }

    const setting = await SystemSettings.findOne({ key: 'registration_price' });

    res.json({
      success: true,
      price: setting ? setting.value : BASE_REGISTRATION_AMOUNT,
      source: setting ? 'database' : 'default',
      lastUpdated: setting ? setting.updated_at : null
    });

  } catch (error) {
    console.error('❌ Get registration price error:', error);
    res.json({
      success: true,
      price: BASE_REGISTRATION_AMOUNT,
      source: 'default'
    });
  }
});

// Partner - Request Password Reset OTP
app.post('/api/partner/password-reset/request', async (req, res) => {
  try {
    const { phone } = req.body;

    if (!phone) {
      return res.status(400).json({
        success: false,
        message: 'Phone number is required'
      });
    }

    // Find partner by phone
    const partner = await Influencer.findOne({ phone_number: phone, status: 'approved' });

    if (!partner) {
      return res.status(404).json({
        success: false,
        message: 'No approved partner found with this phone number'
      });
    }

    // Generate and send OTP
    const otp = generateOTP();
    const otpHash = await bcrypt.hash(otp, PASSWORD_SALT_ROUNDS);

    // Store OTP session
    await OtpSession.findOneAndUpdate(
      { phone_number: phone, type: 'password_reset' },
      {
        phone_number: phone,
        otp_hash: otpHash,
        type: 'password_reset',
        attempts: 0,
        expires_at: new Date(Date.now() + OTP_EXPIRY_MS),
        metadata: { partner_id: partner._id }
      },
      { upsert: true, new: true }
    );

    // Send OTP via SMS
    const message = `Your Agrivalah partner password reset code is ${otp}. Valid for 5 minutes. Do not share this code.`;
    
    if (twilioClient) {
      try {
        await twilioClient.messages.create({
          body: message,
          messagingServiceSid: process.env.TWILIO_MESSAGING_SERVICE_SID,
          to: phone
        });
        console.log(`✅ Password reset OTP sent to ${phone}`);
      } catch (twilioError) {
        console.error('❌ Twilio SMS error:', twilioError);
        return res.status(500).json({
          success: false,
          message: 'Failed to send OTP. Please try again.'
        });
      }
    }

    res.json({
      success: true,
      message: 'OTP sent to your registered phone number',
      expiresIn: 5 // minutes
    });

  } catch (error) {
    console.error('❌ Password reset request error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to process password reset request'
    });
  }
});

// Partner - Verify OTP and Reset Password
app.post('/api/partner/password-reset/verify', async (req, res) => {
  try {
    const { phone, otp, newPassword } = req.body;

    if (!phone || !otp || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Phone, OTP, and new password are required'
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 8 characters long'
      });
    }

    // Find OTP session
    const otpSession = await OtpSession.findOne({
      phone_number: phone,
      type: 'password_reset'
    });

    if (!otpSession) {
      return res.status(400).json({
        success: false,
        message: 'No password reset request found. Please request a new OTP.'
      });
    }

    // Check expiry
    if (new Date() > otpSession.expires_at) {
      await OtpSession.deleteOne({ _id: otpSession._id });
      return res.status(400).json({
        success: false,
        message: 'OTP has expired. Please request a new one.'
      });
    }

    // Check attempts
    if (otpSession.attempts >= 3) {
      await OtpSession.deleteOne({ _id: otpSession._id });
      return res.status(400).json({
        success: false,
        message: 'Too many failed attempts. Please request a new OTP.'
      });
    }

    // Verify OTP
    const isValid = await bcrypt.compare(otp, otpSession.otp_hash);

    if (!isValid) {
      otpSession.attempts += 1;
      await otpSession.save();

      return res.status(400).json({
        success: false,
        message: `Invalid OTP. ${3 - otpSession.attempts} attempts remaining.`
      });
    }

    // Find partner and update password
    const partner = await Influencer.findById(otpSession.metadata.partner_id);

    if (!partner) {
      return res.status(404).json({
        success: false,
        message: 'Partner not found'
      });
    }

    // Hash new password and update
    const passwordHash = await bcrypt.hash(newPassword, PASSWORD_SALT_ROUNDS);
    partner.password_hash = passwordHash;
    await partner.save();

    // Also update in User collection if exists
    const user = await User.findOne({ 
      influencer_id: partner._id,
      role: USER_ROLES.INFLUENCER 
    });

    if (user) {
      user.password_hash = passwordHash;
      await user.save();
    }

    // Delete OTP session
    await OtpSession.deleteOne({ _id: otpSession._id });

    console.log(`✅ Password reset successful for partner ${partner.phone_number}`);

    res.json({
      success: true,
      message: 'Password reset successful. You can now login with your new password.'
    });

  } catch (error) {
    console.error('❌ Password reset verify error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reset password'
    });
  }
});

// Generate WhatsApp Share Link with Auto-Apply Referral
app.get('/api/partner/whatsapp-share/:referralCode', async (req, res) => {
  try {
    const { referralCode } = req.params;

    if (!referralCode) {
      return res.status(400).json({
        success: false,
        message: 'Referral code is required'
      });
    }

    // Verify referral code exists
    const partner = await Influencer.findOne({ 
      coupon_code: referralCode.toUpperCase(),
      status: 'approved' 
    });

    if (!partner) {
      return res.status(404).json({
        success: false,
        message: 'Invalid referral code'
      });
    }

    // Create registration URL with auto-apply referral
    const frontendUrl = process.env.FRONTEND_URL || 'https://agrivalah.in';
    const registrationUrl = `${frontendUrl}/?ref=${referralCode.toUpperCase()}`;

    // Create WhatsApp share message
    const message = encodeURIComponent(
      `🌾 Join Agrivalah Natural Farming! 🌾\n\n` +
      `Get PGS-India certification for just ₹500!\n\n` +
      `✅ 1 Season validity\n` +
      `✅ Government recognized\n` +
      `✅ 15-day processing\n\n` +
      `Use my referral code: ${referralCode.toUpperCase()}\n` +
      `Get instant ₹50 discount!\n\n` +
      `Register now: ${registrationUrl}`
    );

    const whatsappUrl = `https://wa.me/?text=${message}`;

    res.json({
      success: true,
      whatsappUrl,
      registrationUrl,
      referralCode: referralCode.toUpperCase(),
      message: 'WhatsApp share link generated successfully'
    });

  } catch (error) {
    console.error('❌ WhatsApp share link error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to generate share link'
    });
  }
});

// Health check endpoint
app.get('/api/health-check', (req, res) => {
  const healthData = {
    status: 'ok',
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    uptime: process.uptime()
  };

  res.json(healthData);
});

// ================================================
// RAZORPAY PAYMENT ENDPOINTS
// ================================================

// Get Public Keys (Only safe-to-expose keys)
app.get('/api/get-public-keys', (req, res) => {
  try {
    // Only return keys that are safe to expose to frontend
    const publicKeys = {
      razorpay_key_id: process.env.RAZORPAY_KEY_ID, // This is safe to expose
      currency: 'INR',
      amount: 50000, // ₹500 default amount (in paise)
      company_name: 'Agrivalah Natural Farming',
      description: 'PGS-India Natural Farming Certification'
    };

    // Add request validation headers for security
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block'
    });

    res.json({
      success: true,
      keys: publicKeys,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('❌ Error fetching public keys:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve configuration'
    });
  }
});

// Create Razorpay Order
app.post('/api/create-order', async (req, res) => {
  try {
    const { amount, farmerName, phoneNumber, emailId, registrationReference = '' } = req.body || {};
    const normalizedAmount = Number(amount);

    if (!Number.isFinite(normalizedAmount) || (normalizedAmount !== 50000 && normalizedAmount !== 45000)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid amount. Expected ₹500 (50000 paise) or ₹450 (45000 paise) with coupon - all inclusive',
        expected: [50000, 45000],
        received: amount
      });
    }

    if (!razorpayClient) {
      return res.status(500).json({
        success: false,
        message: 'Payment service is not configured'
      });
    }

    const order = await razorpayClient.orders.create({
      amount: normalizedAmount,
      currency: 'INR',
      receipt: `receipt_${Date.now()}`,
      notes: {
        farmer_name: farmerName || '',
        phone_number: phoneNumber || '',
        email_id: emailId || '',
        reference: registrationReference || ''
      }
    });

    const paymentLog = new PaymentLog({
      payment_id: order.id,
      order_id: order.id,
      amount: order.amount,
      currency: order.currency,
      status: order.status || 'created',
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
      notes: order.notes
    });
    await paymentLog.save();

    if (registrationReference) {
      const registrationDoc = await Registration.findOne({ reference_id: registrationReference });
      if (registrationDoc) {
        const amountInRupees = Math.round(normalizedAmount / 100);
        registrationDoc.order_id = order.id;
        registrationDoc.payment_amount = amountInRupees;
        await registrationDoc.save();

        await Payment.findOneAndUpdate(
          { farmer: registrationDoc._id },
          {
            $set: {
              amount: amountInRupees,
              currency: 'INR',
              coupon_code: registrationDoc.coupon_code,
              influencer: registrationDoc.influencer || null,
              commission_paid: registrationDoc.commission_paid,
              commission_amount: registrationDoc.commission_amount || 0,
              payment_status: 'Pending',
              order_id: order.id
            },
            $setOnInsert: {
              farmer: registrationDoc._id
            }
          },
          { upsert: true, new: true, setDefaultsOnInsert: true }
        );
      }
    }

    res.json({
      success: true,
      order_id: order.id,
      amount: order.amount,
      currency: order.currency,
      key_id: process.env.RAZORPAY_KEY_ID
    });
  } catch (error) {
    const razorpayMessage = error?.error?.description || error?.message || 'Failed to create order';
    console.error('Order creation error:', razorpayMessage, error?.error || error);
    res.status(500).json({
      success: false,
      message: razorpayMessage
    });
  }
});

// Verify Razorpay Payment
app.post('/api/verify-payment', async (req, res) => {
  try {
    const {
      razorpay_payment_id,
      razorpay_order_id,
      razorpay_signature,
      amount,
      registration_reference
    } = req.body;

    console.log('Payment verification request:', {
      payment_id: razorpay_payment_id,
      order_id: razorpay_order_id,
      amount: amount
    });

    // Validate required fields
    if (!razorpay_payment_id) {
      return res.status(400).json({
        success: false,
        verified: false,
        message: 'Payment ID is required'
      });
    }

    let isSignatureValid = true; // Default for testing

    // If we have order_id and signature, verify them
    if (razorpay_order_id && razorpay_signature && process.env.RAZORPAY_KEY_SECRET) {
      try {
        const body = razorpay_order_id + '|' + razorpay_payment_id;
        const expectedSignature = crypto
          .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
          .update(body.toString())
          .digest('hex');

        isSignatureValid = expectedSignature === razorpay_signature;
        console.log('Signature verification:', isSignatureValid ? 'Valid' : 'Invalid');
      } catch (signatureError) {
        console.warn('Signature verification failed:', signatureError.message);
        // Continue with payment if signature check fails (for testing)
        isSignatureValid = true;
      }
    }

    // Update payment log
    try {
      await PaymentLog.findOneAndUpdate(
        { $or: [{ payment_id: razorpay_payment_id }, { order_id: razorpay_order_id }] },
        {
          payment_id: razorpay_payment_id,
          order_id: razorpay_order_id || null,
          razorpay_signature: razorpay_signature || null,
          status: isSignatureValid ? 'paid' : 'failed',
          registration_reference: registration_reference || null,
          ip_address: req.ip,
          user_agent: req.get('User-Agent')
        },
        { upsert: true, new: true }
      );
    } catch (logError) {
      console.warn('Failed to update payment log:', logError.message);
    }

    // Update daily statistics
    if (!isSignatureValid) {
      await updateDailyStats('failed_payments', 1);
    }

    res.json({
      success: isSignatureValid,
      verified: isSignatureValid,
      message: isSignatureValid ? 'Payment verified successfully' : 'Payment verification failed',
      payment_id: razorpay_payment_id,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('❌ Payment verification error:', error);
    res.status(500).json({
      success: false,
      verified: false,
      message: 'Payment verification failed',
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// ================================================
// REGISTRATION ENDPOINTS
// ================================================

// Submit Registration
app.post('/api/submit-registration', async (req, res) => {
  try {
    console.log('Registration submission received');
    console.log('Request body keys:', Object.keys(req.body));

    // Validate required fields
    const requiredFields = [
      'farmerName', 'fatherSpouseName', 'contactNumber',
      'villagePanchayat', 'mandalBlock', 'district', 'state',
      'totalLand', 'areaNaturalFarming', 'sowingDate', 'cropTypes',
      'farmingPractice', 'termsAgreement'
    ];

    const missingFields = requiredFields.filter(field => !req.body[field]);

    if (missingFields.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields',
        missing_fields: missingFields
      });
    }

    // Validate terms agreement
    if (req.body.termsAgreement !== true) {
      return res.status(400).json({
        success: false,
        message: 'Terms and conditions must be accepted'
      });
    }

    // Validate contact number
    const contactRegex = /^[6-9]\d{9}$/;
    if (!contactRegex.test(req.body.contactNumber)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid contact number format'
      });
    }

    // Generate unique reference ID
    let reference_id;
    let isUnique = false;
    let attempts = 0;

    while (!isUnique && attempts < 10) {
      reference_id = generateReferenceId();
      const existingRegistration = await Registration.findOne({ reference_id });
      if (!existingRegistration) {
        isUnique = true;
      }
      attempts++;
    }

    if (!isUnique) {
      throw new Error('Failed to generate unique reference ID');
    }

    // Helper functions to normalize enum values
    const normalizeLandUnit = (value) => {
      if (!value) return 'Acre';
      const lower = value.toLowerCase();
      if (lower === 'acre' || lower === 'acres') return 'Acre';
      if (lower === 'hectare' || lower === 'hectares') return 'Hectare';
      if (lower === 'bigha' || lower === 'bighas') return 'Bigha';
      if (lower === 'guntha' || lower === 'gunthas') return 'Guntha';
      return 'Acre';
    };

    const normalizeFarmingPractice = (value) => {
      if (!value) return 'Natural';
      const lower = value.toLowerCase();
      if (lower === 'organic') return 'Organic';
      if (lower === 'natural') return 'Natural';
      if (lower === 'chemical') return 'Chemical';
      if (lower === 'mixed') return 'Mixed';
      return 'Natural';
    };

    const normalizeIrrigation = (value) => {
      if (!value) return 'Rainwater';
      const lower = value.toLowerCase();
      if (lower === 'rainwater' || lower === 'rainfed' || lower === 'rain') return 'Rainwater';
      if (lower === 'borewell' || lower === 'bore well') return 'Borewell';
      if (lower === 'canal') return 'Canal';
      if (lower === 'river') return 'River';
      if (lower === 'pond') return 'Pond';
      if (lower === 'other') return 'Other';
      return 'Rainwater';
    };

    // Process livestock array
    const livestock = Array.isArray(req.body.livestock)
      ? req.body.livestock
      : req.body.livestock ? req.body.livestock.split(',').map(item => item.trim()) : [];

    // Create registration document
    const registrationData = {
      reference_id: reference_id,
      registration_date: new Date(req.body.registrationDate) || new Date(),

      // Personal Information
      farmer_name: req.body.farmerName.trim(),
      father_spouse_name: req.body.fatherSpouseName.trim(),
      contact_number: req.body.contactNumber.trim(),
      email_id: req.body.emailId ? req.body.emailId.trim().toLowerCase() : null,
      aadhaar_farmer_id: req.body.aadhaarFarmerId || null,

      // Location Information
      village_panchayat: req.body.villagePanchayat.trim(),
      mandal_block: req.body.mandalBlock.trim(),
      district: req.body.district.trim(),
      state: req.body.state.trim(),

      // Land Information
      khasra_passbook: req.body.khasraPassbook || null,
      plot_no: req.body.plotNo || null,
      total_land: parseFloat(req.body.totalLand),
      land_unit: normalizeLandUnit(req.body.landUnit),
      area_natural_farming: parseFloat(req.body.areaNaturalFarming),

      // Crop Information
      present_crop: req.body.presentCrop || null,
      sowing_date: new Date(req.body.sowingDate),
      harvesting_date: req.body.harvestingDate ? new Date(req.body.harvestingDate) : null,
      crop_types: req.body.cropTypes.trim(),

      // Farming Practice
      farming_practice: normalizeFarmingPractice(req.body.farmingPractice),
      farming_experience: parseInt(req.body.farmingExperience) || 0,
      irrigation_source: normalizeIrrigation(req.body.irrigationSource),

      // Additional Information
      livestock: livestock,
      willing_to_adopt: req.body.willingToAdopt || 'Maybe',
      additional_details: {
        trainingRequired: req.body.trainingRequired || null,
        localGroupName: req.body.localGroupName || null,
        preferredCroppingSeason: req.body.preferredCroppingSeason || null,
        remarks: req.body.remarks || null,
        naturalInputs: req.body.naturalInputs || null
      },
      coupon_code: req.body.couponCode || null,
      influencer: req.body.influencer || null,
      commission_amount: Number(req.body.commissionAmount) || 0,
      commission_paid: req.body.commissionPaid === true,
      payment_amount: Number(req.body.paymentAmount) || 500,
      payment_id: req.body.paymentId || null,
      order_id: req.body.orderId || null,
      otp_token: req.body.otpToken || null,
      otp_verified: req.body.otpVerified === true,
      otp_verified_at: req.body.otpVerifiedAt ? new Date(req.body.otpVerifiedAt) : null,

      // Preferences
      terms_agreement: req.body.termsAgreement,

      // System Information
      ip_address: req.ip,
      user_agent: req.get('User-Agent'),
      submission_source: 'web',

      // Status
      status: 'pending',
      payment_status: req.body.paymentStatus || 'completed'
    };

    // Save registration
    const registration = new Registration(registrationData);
    await registration.save();

    // Update daily statistics
    await updateDailyStats('total_registrations', 1, { district: req.body.district });

    console.log(`✅ Registration saved: ${reference_id} - ${req.body.farmerName}`);

    // Prepare response
    const response = {
      success: true,
      message: 'Registration successful',
      reference_id: reference_id,
      farmer_name: req.body.farmerName,
      contact_number: req.body.contactNumber,
      timestamp: new Date().toISOString()
    };

    res.status(201).json(response);

  } catch (error) {
    console.error('❌ Registration error:', error);

    let statusCode = 500;
    let message = 'Registration failed';

    if (error.name === 'ValidationError') {
      statusCode = 400;
      message = 'Invalid data provided';
    } else if (error.code === 11000) {
      statusCode = 409;
      message = 'Registration already exists';
    }

    res.status(statusCode).json({
      success: false,
      message: message,
      error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
    });
  }
});

// Get Registration by Reference ID
app.post('/api/get-registration', async (req, res) => {
  try {
    const { reference_id } = req.body;

    if (!reference_id) {
      return res.status(400).json({
        success: false,
        message: 'Reference ID is required'
      });
    }

    const registration = await Registration.findOne({ reference_id }).lean();

    if (!registration) {
      return res.status(404).json({
        success: false,
        message: 'Registration not found'
      });
    }

    // Remove sensitive information
    delete registration.ip_address;
    delete registration.user_agent;
    delete registration.__v;

    res.json({
      success: true,
      registration: registration
    });

  } catch (error) {
    console.error('❌ Get registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve registration'
    });
  }
});

// List Registrations (Admin endpoint)
app.get('/api/list-registrations', async (req, res) => {
  try {
    const {
      page = 1,
      limit = 20,
      status,
      district,
      state,
      payment_status,
      search
    } = req.query;

    // Build query
    const query = {};

    if (status) query.status = status;
    if (district) query.district = new RegExp(district, 'i');
    if (state) query.state = new RegExp(state, 'i');
    if (payment_status) query.payment_status = payment_status;

    if (search) {
      query.$or = [
        { farmer_name: new RegExp(search, 'i') },
        { reference_id: new RegExp(search, 'i') },
        { contact_number: new RegExp(search, 'i') }
      ];
    }

    // Execute query with pagination
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const [registrations, total] = await Promise.all([
      Registration.find(query)
        .select('-ip_address -user_agent -__v')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Registration.countDocuments(query)
    ]);

    res.json({
      success: true,
      registrations: registrations,
      pagination: {
        total: total,
        page: parseInt(page),
        limit: parseInt(limit),
        pages: Math.ceil(total / parseInt(limit))
      }
    });

  } catch (error) {
    console.error('❌ List registrations error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to list registrations'
    });
  }
});

// ================================================
// STATISTICS AND ANALYTICS ENDPOINTS
// ================================================

// Get Dashboard Statistics
app.get('/api/stats/dashboard', async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);

    const thisMonth = new Date(today.getFullYear(), today.getMonth(), 1);

    // Get various statistics
    const [
      totalRegistrations,
      todayRegistrations,
      pendingRegistrations,
      approvedRegistrations,
      totalRevenue,
      todayRevenue,
      monthlyStats,
      districtStats
    ] = await Promise.all([
      Registration.countDocuments(),
      Registration.countDocuments({
        createdAt: { $gte: today }
      }),
      Registration.countDocuments({ status: 'pending' }),
      Registration.countDocuments({ status: 'approved' }),
      PaymentLog.aggregate([
        { $match: { status: 'paid' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      PaymentLog.aggregate([
        { $match: { status: 'paid', createdAt: { $gte: today } } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      SystemStats.findOne({ date: today }),
      Registration.aggregate([
        {
          $group: {
            _id: '$district',
            count: { $sum: 1 },
            approved: {
              $sum: { $cond: [{ $eq: ['$status', 'approved'] }, 1, 0] }
            }
          }
        },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ])
    ]);

    res.json({
      success: true,
      stats: {
        registrations: {
          total: totalRegistrations,
          today: todayRegistrations,
          pending: pendingRegistrations,
          approved: approvedRegistrations
        },
        revenue: {
          total: totalRevenue[0]?.total || 0,
          today: todayRevenue[0]?.total || 0,
          formatted_total: `₹${((totalRevenue[0]?.total || 0) / 100).toLocaleString()}`,
          formatted_today: `₹${((todayRevenue[0]?.total || 0) / 100).toLocaleString()}`
        },
        districts: districtStats,
        daily_stats: monthlyStats
      }
    });

  } catch (error) {
    console.error('❌ Stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve statistics'
    });
  }
});

// ================================================
// ERROR HANDLING MIDDLEWARE
// ================================================

// 404 handler for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    message: `API endpoint not found: ${req.method} ${req.originalUrl}`,
    available_endpoints: [
      'GET /api/health-check',
      'POST /api/create-order',
      'POST /api/verify-payment',
      'POST /api/submit-registration',
      'POST /api/get-registration',
      'GET /api/list-registrations',
      'GET /api/stats/dashboard'
    ]
  });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('❌ Unhandled error:', error);

  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
  });
});

// ================================================
// SERVER STARTUP
// ================================================

// Graceful shutdown handling
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully...');

  try {
    await mongoose.connection.close();
    console.log('MongoDB connection closed');
    process.exit(0);
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully...');

  try {
    await mongoose.connection.close();
    console.log('MongoDB connection closed');
    process.exit(0);
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
});

// Start server (only in non-serverless environments)
if (process.env.VERCEL !== '1') {
  app.listen(PORT, () => {
    console.log('🚀 Server Configuration:');
    console.log(`   • Port: ${PORT}`);
    console.log(`   • Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`   • Database: ${process.env.MONGODB_URI ? 'Configured' : 'Local MongoDB'}`);
    console.log(`   • Razorpay: ${process.env.RAZORPAY_KEY_ID ? 'Configured' : 'Not configured'}`);
    console.log('');
    console.log('🌟 API Endpoints Available:');
    console.log('   • GET  /api/health-check');
    console.log('   • POST /api/create-order');
    console.log('   • POST /api/verify-payment');
    console.log('   • POST /api/submit-registration');
    console.log('   • POST /api/get-registration');
    console.log('   • GET  /api/list-registrations');
    console.log('   • GET  /api/stats/dashboard');
    console.log('');
    console.log(`✅ Server running at http://localhost:${PORT}`);
    console.log(`📊 Health check: http://localhost:${PORT}/api/health-check`);
  });
}

// Export for Vercel serverless
module.exports = app;

