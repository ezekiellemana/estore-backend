// server.js

// ────────────────────────────────
// IMPORTS & SETUP
// ────────────────────────────────
const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const { OAuth2Client } = require('google-auth-library');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const { body, query, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const cron = require('node-cron');
const multer = require('multer');
const { Parser } = require('json2csv');
const { randomUUID } = require('crypto');

dotenv.config();

const app = express();
app.set('trust proxy', 1); // for deployment

// ────────────────────────────────
// CORS (Dev + Prod Support!)
// ────────────────────────────────
const allowedOrigins = [
  'http://localhost:5173',
  process.env.FRONTEND_URL
];
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
};
app.use(cors(corsOptions));

// ────────────────────────────────
// SESSION, COOKIES, BODY PARSE
// ────────────────────────────────
app.use(express.json());
app.use(cookieParser());

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'secretkey',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: 'sessions',
      ttl: 60 * 60 * 24 * 7,
    }),
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

// ────────────────────────────────
// PASSPORT INIT
// ────────────────────────────────
app.use(passport.initialize());
app.use(passport.session());

// ────────────────────────────────
// GUEST ID COOKIE + SANITIZE
// ────────────────────────────────
app.use((req, res, next) => {
  if (req.headers.authorization?.startsWith('Bearer ')) return next();
  if (req.cookies?.guestId) return next();
  res.cookie('guestId', randomUUID(), { httpOnly: true, sameSite: 'lax' });
  next();
});
const sanitizeInput = (req, res, next) => {
  const cleanObject = (obj) => {
    for (const key in obj) {
      if (typeof obj[key] === 'string') obj[key] = obj[key].replace(/[$][\w]+/g, '');
      else if (typeof obj[key] === 'object' && obj[key] !== null) cleanObject(obj[key]);
    }
    return obj;
  };
  if (req.body) req.body = cleanObject(req.body);
  if (req.query) req.query = cleanObject(req.query);
  if (req.params) req.params = cleanObject(req.params);
  next();
};
app.use(sanitizeInput);

// ────────────────────────────────
// DB SCHEMAS
// ────────────────────────────────

// USER
const userSchema = new mongoose.Schema({
  name: { type: String, required: [true, 'Name is required'], trim: true },
  email: { type: String, required: [true, 'Email is required'], unique: true, lowercase: true, trim: true },
  password: { type: String, required: [true, 'Password is required'], select: false },
  isAdmin: { type: Boolean, default: false },
  address: {
    street: { type: String, default: '' },
    city: { type: String, default: '' },
    country: { type: String, default: '' },
    postalCode: { type: String, default: '' },
  },
  wishlist: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
  passwordResetToken: String,
  passwordResetExpires: Date,
  oauthProvider: String,
  oauthId: String,
  createdAt: { type: Date, default: Date.now },
});
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});
userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
  return resetToken;
};
const User = mongoose.model('User', userSchema);

// CATEGORY
const categorySchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  description: { type: String },
});
const Category = mongoose.model('Category', categorySchema);

// PRODUCT
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  price: { type: Number, required: true },
  discount: { type: Number, default: 0 },
  stock: { type: Number, required: true },
  category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true },
  images: [{ type: String }],
  variantOptions: [
    {
      name: { type: String, required: true },
      values: [{ type: String, required: true }],
    },
  ],
  avgRating: { type: Number, default: 0 },
  reviewCount: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});
productSchema.pre('save', async function (next) {
  if (this.isModified('stock') && this.stock <= 5) {
    console.log(`Low stock alert: Product "${this.name}" has ${this.stock} units remaining.`);
  }
  next();
});
const Product = mongoose.model('Product', productSchema);

// REVIEW
const reviewSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
  rating: { type: Number, required: true, min: 1, max: 5 },
  comment: { type: String },
  verifiedPurchase: { type: Boolean, default: false },
  reactions: {
    helpful: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    funny: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    angry: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  },
  adminReply: { message: { type: String }, date: { type: Date } },
  createdAt: { type: Date, default: Date.now },
});
const Review = mongoose.model('Review', reviewSchema);

// REACTION
const reactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  review: { type: mongoose.Schema.Types.ObjectId, ref: 'Review', required: true },
  type: { type: String, enum: ['helpful', 'funny', 'angry'], required: true },
  createdAt: { type: Date, default: Date.now },
});
reactionSchema.index({ user: 1, review: 1, type: 1 }, { unique: true });
const Reaction = mongoose.model('Reaction', reactionSchema);

// CART
const cartSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', unique: true, sparse: true },
  guestId: { type: String, unique: true, sparse: true },
  items: [
    {
      product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
      quantity: { type: Number, required: true, min: 1 },
    },
  ],
  updatedAt: { type: Date, default: Date.now },
});
const Cart = mongoose.model('Cart', cartSchema);

// ORDER
const orderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [
    {
      product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
      quantity: { type: Number, required: true, min: 1 },
      price: { type: Number, required: true },
    },
  ],
  total: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'cancelled'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
});
const Order = mongoose.model('Order', orderSchema);

// ────────────────────────────────
// PASSPORT STRATEGIES
// ────────────────────────────────
passport.serializeUser((user, done) => done(null, user._id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.OAUTH_CALLBACK,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ oauthProvider: 'google', oauthId: profile.id });
        if (!user) {
          user = await User.create({
            oauthProvider: 'google',
            oauthId: profile.id,
            name: profile.displayName,
            email: profile.emails[0].value,
            password: await bcrypt.hash(randomUUID(), 10),
          });
        }
        done(null, user);
      } catch (err) {
        done(err);
      }
    }
  )
);
passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: process.env.OAUTH_CALLBACK,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ oauthProvider: 'github', oauthId: profile.id });
        if (!user) {
          user = await User.create({
            oauthProvider: 'github',
            oauthId: profile.id,
            name: profile.username,
            email: profile.emails[0].value,
            password: await bcrypt.hash(randomUUID(), 10),
          });
        }
        done(null, user);
      } catch (err) {
        done(err);
      }
    }
  )
);

// ────────────────────────────────
// NODEMAILER TRANSPORTER
// ────────────────────────────────
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT),
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ────────────────────────────────
// PASSPORT CALLBACK ROUTES
// ────────────────────────────────
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect(`${process.env.FRONTEND_URL}/oauth-success`);
  }
);

// ────────────────────────────────
// DB CONNECT
// ────────────────────────────────
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err));

// ────────────────────────────────
// HELPER FUNCTIONS & MIDDLEWARES
// ────────────────────────────────
const authMiddleware = async (req, res, next) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  req.user = await User.findById(req.session.userId);
  if (!req.user) return res.status(401).json({ error: 'User not found' });
  next();
};
const adminMiddleware = (req, res, next) => {
  if (!req.user?.isAdmin) return res.status(403).json({ error: 'Admin access required' });
  next();
};
// Optional auth for reviews etc
const optionalAuth = async (req, res, next) => {
  if (req.session && req.session.userId) {
    req.user = await User.findById(req.session.userId);
  }
  next();
};
const getCartQuery = (req) => req.user && req.user._id ? { user: req.user._id } : { guestId: req.cookies.guestId };

// ────────────────────────────────
// RATE LIMITERS
// ────────────────────────────────
const authLimiter = rateLimit({ windowMs: 60 * 1000, max: 50, message: 'Too many requests, slow down.' });
app.use('/api/users/login', authLimiter);
app.use('/api/users/forgot-password', authLimiter);

// ────────────────────────────────────────────────────────────────────────────────
// ROUTES: USERS (REGISTER, LOGIN, LOGOUT, PROFILE, FORGOT/RESET PASSWORD, ADMIN)
// ────────────────────────────────────────────────────────────────────────────────

// REGISTER
app.post(
  '/api/users/register',
  [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be 6+ chars'),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { name, email, password } = req.body;
      const existing = await User.findOne({ email });
      if (existing) return res.status(400).json({ error: 'Email already in use' });

      const user = new User({ name, email, password });
      await user.save();
      // Optionally auto-login after register:
      req.session.userId = user._id;
      res.status(201).json({ message: 'User registered', user: { ...user.toObject(), password: undefined } });
    } catch (err) {
      next(err);
    }
  }
);

// LOGIN (creates session)
app.post(
  '/api/users/login',
  [
    body('email').isEmail().withMessage('Valid email is required'),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email }).select('+password');
      if (!user) return res.status(400).json({ error: 'Invalid credentials' });

      const match = await bcrypt.compare(password, user.password);
      if (!match) return res.status(400).json({ error: 'Invalid credentials' });

      req.session.userId = user._id; // Save to session
      res.json({ message: 'Login successful' });
    } catch (err) {
      next(err);
    }
  }
);
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

app.post('/api/users/google-login', async (req, res) => {
  const { token } = req.body;
  try {
    // 1. Verify with Google
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    // 2. Find or create your user in DB
    let user = await User.findOne({ googleId });
    if (!user) {
      user = await User.create({ googleId, email, name, avatar: picture });
    }

    // 3. Generate your JWT/session exactly like your regular login
    const jwtToken = user.getSignedJwtToken();
    res.cookie('token', jwtToken, { httpOnly: true, secure: true });
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Invalid Google token' });
  }
});
// LOGOUT (destroy session)
app.post('/api/users/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ message: 'Logged out' });
  });
});

// GET PROFILE
app.get('/api/users/profile', authMiddleware, async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    res.json(user);
  } catch (err) {
    next(err);
  }
});

// UPDATE PROFILE
app.put(
  '/api/users/profile',
  authMiddleware,
  [
    body('name').optional().notEmpty().withMessage('Name cannot be empty'),
    body('email').optional().isEmail().withMessage('Valid email is required'),
    body('address.street').optional().trim(),
    body('address.city').optional().trim(),
    body('address.country').optional().trim(),
    body('address.postalCode').optional().trim(),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { name, email, address } = req.body;
      const updateData = {};
      if (name) updateData.name = name;
      if (email) {
        const existingUser = await User.findOne({ email, _id: { $ne: req.user._id } });
        if (existingUser) return res.status(400).json({ error: 'Email already exists' });
        updateData.email = email;
      }
      if (address) updateData.address = address;

      const user = await User.findByIdAndUpdate(req.user._id, updateData, { new: true }).select(
        '-password'
      );
      res.json({ message: 'Profile updated', user });
    } catch (error) {
      next(error);
    }
  }
);

// UPDATE PASSWORD
app.put(
  '/api/users/password',
  authMiddleware,
  [
    body('currentPassword').notEmpty().withMessage('Current password is required'),
    body('newPassword').isLength({ min: 6 }).withMessage('New password must be at least 6 characters'),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const user = await User.findById(req.user._id).select('+password');
      if (!user) return res.status(404).json({ error: 'User not found' });

      const match = await bcrypt.compare(req.body.currentPassword, user.password);
      if (!match) return res.status(400).json({ error: 'Current password is incorrect' });

      user.password = await bcrypt.hash(req.body.newPassword, 10);
      await user.save();

      res.json({ message: 'Password updated successfully' });
    } catch (err) {
      next(err);
    }
  }
);

// GET ALL USERS (ADMIN ONLY)
app.get('/api/users', authMiddleware, adminMiddleware, async (req, res, next) => {
  try {
    const users = await User.find({}).sort({ createdAt: -1 }).select('-password');
    res.json(users);
  } catch (err) {
    next(err);
  }
});

// FORGOT PASSWORD
app.post('/api/users/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Please provide your email address.' });
  }

  try {
    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(200).json({
        message: 'If that account exists, you will receive a password reset link shortly.',
      });
    }

    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    const resetURL = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    const mailOptions = {
      from: `"eStore Support" <${process.env.ADMIN_EMAIL}>`,
      to: user.email,
      subject: '🔒 Your eStore Password Reset Link (expires in 10 minutes)',
      text: `Hi ${user.name},

You requested a password reset. Click the link below to set a new password. This link will expire in 10 minutes:

${resetURL}

If you did not request this, please ignore this email.

Thanks,
eStore Team
`,
      html: `
        <p>Hi ${user.name},</p>
        <p>You requested a password reset. Click the link below to set a new password (valid for 10 minutes):</p>
        <p><a href="${resetURL}">${resetURL}</a></p>
        <p>If you did not request this, please ignore this email.</p>
        <p>Thanks,<br>eStore Team</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    res.status(200).json({
      message: 'If that account exists, you will receive a password reset link shortly.',
    });
  } catch (err) {
    console.error('Error in POST /api/users/forgot-password:', err);
    res.status(500).json({ error: 'Server error while sending reset link. Please try again.' });
  }
});


// RESET PASSWORD
app.post('/api/users/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;
  if (!password || password.length < 6) {
    return res
      .status(400)
      .json({ error: 'New password must be at least 6 characters.' });
  }

  try {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    }).select('+password');

    if (!user) {
      return res.status(400).json({ error: 'Token is invalid or has expired.' });
    }

    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    res.status(200).json({ message: 'Password has been reset successfully.' });
  } catch (err) {
    console.error('Error in POST /api/users/reset-password/:token:', err);
    res
      .status(500)
      .json({ error: 'Server error while resetting password. Please try again.' });
  }
});

// ────────────────────────────────────────────────────────────────────────────────
// ROUTES: CATEGORIES (CRUD, ADMIN)
// ────────────────────────────────────────────────────────────────────────────────

app.post(
  '/api/categories',
  authMiddleware,
  adminMiddleware,
  [body('name').notEmpty().withMessage('Name is required')],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { name, description } = req.body;
      const existing = await Category.findOne({ name: name.trim() });
      if (existing) return res.status(400).json({ error: 'Category already exists' });

      const category = new Category({ name: name.trim(), description });
      await category.save();
      res.status(201).json(category);
    } catch (err) {
      next(err);
    }
  }
);

app.get('/api/categories', async (req, res, next) => {
  try {
    const categories = await Category.find().sort({ name: 1 });
    res.json(categories);
  } catch (err) {
    next(err);
  }
});

app.put(
  '/api/categories/:id',
  authMiddleware,
  adminMiddleware,
  [body('name').notEmpty().withMessage('Name is required')],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const category = await Category.findById(req.params.id);
      if (!category) return res.status(404).json({ error: 'Category not found' });

      category.name = req.body.name.trim();
      category.description = req.body.description || '';
      await category.save();
      res.json(category);
    } catch (err) {
      next(err);
    }
  }
);

app.delete(
  '/api/categories/:id',
  authMiddleware,
  adminMiddleware,
  async (req, res, next) => {
    try {
      const category = await Category.findByIdAndDelete(req.params.id);
      if (!category) return res.status(404).json({ error: 'Category not found' });
      res.json({ message: 'Category deleted' });
    } catch (err) {
      next(err);
    }
  }
);

// ────────────────────────────────────────────────────────────────────────────────
// ROUTES: PRODUCTS (CRUD, SEARCH + PAGINATION, ADMIN)
// ────────────────────────────────────────────────────────────────────────────────

app.post(
  '/api/products',
  authMiddleware,
  adminMiddleware,
  [
    body('name').notEmpty().withMessage('Product name is required'),
    body('price').isFloat({ min: 0 }).withMessage('Price must be a positive number'),
    body('stock').isInt({ min: 0 }).withMessage('Stock must be a non-negative integer'),
    body('category').notEmpty().withMessage('Category ID is required'),
    body('discount').optional().isFloat({ min: 0, max: 100 }).withMessage('Discount must be between 0 and 100'),
    body('images').optional().isArray().withMessage('Images must be an array of URLs'),
    body('images.*').optional().isURL().withMessage('Each image must be a valid URL'),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { name, description, price, stock, category, discount, images } = req.body;
      const categoryExists = await Category.findById(category);
      if (!categoryExists) return res.status(400).json({ error: 'Invalid category ID' });

      const product = new Product({ name, description, price, stock, category, discount, images });
      await product.save();
      res.status(201).json({ message: 'Product created', product });
    } catch (error) {
      next(error);
    }
  }
);

app.delete(
  '/api/products/:id',
  authMiddleware,
  adminMiddleware,
  async (req, res, next) => {
    try {
      const deleted = await Product.findByIdAndDelete(req.params.id);
      if (!deleted) return res.status(404).json({ error: 'Product not found' });
      res.json({ message: 'Product deleted' });
    } catch (error) {
      next(error);
    }
  }
);

app.put(
  '/api/products/:id',
  authMiddleware,
  adminMiddleware,
  [
    body('name').optional().notEmpty(),
    body('price').optional().isFloat({ min: 0 }),
    body('stock').optional().isInt({ min: 0 }),
    body('discount').optional().isFloat({ min: 0, max: 100 }),
    body('images').optional().isArray(),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const updated = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
      if (!updated) return res.status(404).json({ error: 'Product not found' });
      res.json({ message: 'Product updated', product: updated });
    } catch (err) {
      next(err);
    }
  }
);

// GET /api/products (search, filters, pagination, rating aggregation)
app.get(
  '/api/products',
  [
    query('search').optional().trim(),
    query('category').optional().trim(),
    query('minPrice').optional().isFloat({ min: 0 }),
    query('maxPrice').optional().isFloat({ min: 0 }),
    query('page').optional().isInt({ min: 1 }),
    query('limit').optional().isInt({ min: 1 }),
    query('discounted').optional().isBoolean(),
    query('inStock').optional().isBoolean(),
    query('sort').optional().isString(),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const {
        search,
        category,
        minPrice,
        maxPrice,
        page = 1,
        limit = 10,
        discounted,
        inStock,
        sort,
      } = req.query;

      const queryObj = {};

      if (search) {
        queryObj.name = { $regex: search, $options: 'i' };
      }
      if (category) {
        queryObj.category = category;
      }
      if (minPrice || maxPrice) {
        queryObj.price = {};
        if (minPrice) queryObj.price.$gte = parseFloat(minPrice);
        if (maxPrice) queryObj.price.$lte = parseFloat(maxPrice);
      }
      if (discounted === 'true') {
        queryObj.discount = { $gt: 0 };
      }
      if (inStock === 'true') {
        queryObj.stock = { $gt: 0 };
      }

      const skip = (parseInt(page, 10) - 1) * parseInt(limit, 10);

      // Sorting options
      const sortOptions = {
        price_asc: { price: 1 },
        price_desc: { price: -1 },
        rating_desc: { avgRating: -1 }, // will adjust in JS
        newest: { createdAt: -1 },
      };
      const sortQuery = sortOptions[sort] || { createdAt: -1 };

      const products = await Product.find(queryObj)
        .populate('category')
        .sort(sortQuery)
        .skip(skip)
        .limit(parseInt(limit, 10));

      const total = await Product.countDocuments(queryObj);
      const productIds = products.map((p) => p._id);

      // Aggregate ratings
      const ratings = await Review.aggregate([
        { $match: { product: { $in: productIds } } },
        {
          $group: {
            _id: '$product',
            avgRating: { $avg: '$rating' },
            totalReviews: { $sum: 1 },
          },
        },
      ]);

      const ratingMap = {};
      ratings.forEach((r) => {
        ratingMap[r._id.toString()] = {
          avgRating: Math.round(r.avgRating * 10) / 10,
          totalReviews: r.totalReviews,
        };
      });

      let productsWithRatings = products.map((p) => {
        const { avgRating = 0, totalReviews = 0 } =
          ratingMap[p._id.toString()] || {};
        return {
          ...p.toObject(),
          avgRating,
          totalReviews,
        };
      });

      // If sorting by rating, do it here
      if (sort === 'rating_desc') {
        productsWithRatings = productsWithRatings.sort(
          (a, b) => b.avgRating - a.avgRating
        );
      }

      res.json({
        products: productsWithRatings,
        totalPages: Math.ceil(total / parseInt(limit, 10)),
        currentPage: parseInt(page, 10),
      });
    } catch (error) {
      next(error);
    }
  }
);

// GET /api/products/:id (with rating)
app.get('/api/products/:id', async (req, res, next) => {
  const { id } = req.params;
  if (!mongoose.isValidObjectId(id)) {
    return res.status(400).json({ error: 'Invalid product ID format.' });
  }

  try {
    const product = await Product.findById(id).populate('category');
    if (!product) {
      return res.status(404).json({ error: 'Product not found.' });
    }

    const [ratingStats] = await Review.aggregate([
      { $match: { product: product._id } },
      {
        $group: {
          _id: null,
          avgRating: { $avg: '$rating' },
          totalReviews: { $sum: 1 },
        },
      },
    ]);

    const avgRating = ratingStats?.avgRating || 0;
    const totalReviews = ratingStats?.totalReviews || 0;

    return res.json({
      ...product.toObject(),
      avgRating: Math.round(avgRating * 10) / 10,
      totalReviews,
    });
  } catch (err) {
    console.error('Error in GET /api/products/:id →', err.message);
    console.error(err.stack);
    return res.status(500).json({ error: 'Server error. Please try again later.' });
  }
});

// ────────────────────────────────────────────────────────────────────────────────
// ROUTES: REVIEWS (CRUD, REACTIONS, ADMIN)
// ────────────────────────────────────────────────────────────────────────────────

app.post(
  '/api/reviews',
  authMiddleware,
  [
    body('productId').notEmpty().withMessage('Product ID is required'),
    body('rating').isInt({ min: 1, max: 5 }).withMessage('Rating must be between 1 and 5'),
    body('comment').optional().trim(),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { productId, rating, comment } = req.body;
      const product = await Product.findById(productId);
      if (!product) return res.status(400).json({ error: 'Product not found' });

      const existing = await Review.findOne({ user: req.user._id, product: productId });
      if (existing) return res.status(400).json({ error: 'You have already reviewed this product' });

      const hasOrdered = await Order.exists({
        user: req.user._id,
        'items.product': productId,
      });

      const review = new Review({
        user: req.user._id,
        product: productId,
        rating,
        comment,
        verifiedPurchase: !!hasOrdered,
      });

      await review.save();
      res.status(201).json({ message: 'Review added', review });
    } catch (err) {
      next(err);
    }
  }
);

app.post(
  '/api/products/:id/reviews',
  authMiddleware,
  [
    body('rating')
      .isInt({ min: 1, max: 5 })
      .withMessage('Rating must be between 1 and 5'),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const product = await Product.findById(req.params.id);
      if (!product) return res.status(404).json({ error: 'Product not found' });

      const existing = await Review.findOne({
        user: req.user._id,
        product: product._id,
      });
      if (existing) {
        return res.status(400).json({ error: 'You have already reviewed this product' });
      }

      const { rating, comment } = req.body;
      const review = new Review({
        user: req.user._id,
        product: product._id,
        rating,
        comment,
        verifiedPurchase: false,
      });
      await review.save();

      res.status(201).json({ message: 'Review added', review });
    } catch (err) {
      next(err);
    }
  }
);

app.get('/api/reviews/:productId', optionalAuth, async (req, res, next) => {
  try {
    const reviews = await Review.find({ product: req.params.productId }).populate('user', 'name');
    const userId = req.user?._id?.toString();

    const enriched = reviews.map((review) => {
      const reviewObj = review.toObject();
      if (userId) {
        const found = review.reactions?.helpful.find((u) => u.toString() === userId)
          ? 'helpful'
          : review.reactions?.funny.find((u) => u.toString() === userId)
          ? 'funny'
          : review.reactions?.angry.find((u) => u.toString() === userId)
          ? 'angry'
          : null;
        reviewObj.userReactionType = found;
      }
      return reviewObj;
    });

    res.json(enriched);
  } catch (error) {
    next(error);
  }
});

app.post(
  '/api/reviews/:id',
  authMiddleware,
  [body('rating').isInt({ min: 1, max: 5 }).withMessage('Rating 1–5 required')],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const review = await Review.findById(req.params.id);
      if (!review) return res.status(404).json({ error: 'Review not found' });

      if (!review.user.equals(req.user._id)) return res.status(403).json({ error: 'Not allowed' });

      review.rating = req.body.rating;
      review.comment = req.body.comment;
      await review.save();
      res.json({ message: 'Review updated', review });
    } catch (err) {
      next(err);
    }
  }
);

app.delete('/api/reviews/:id', authMiddleware, async (req, res, next) => {
  try {
    const review = await Review.findById(req.params.id);
    if (!review) {
      return res.status(404).json({ error: 'Review not found' });
    }

    if (!review.user.equals(req.user._id) && req.user.isAdmin !== true) {
      return res.status(403).json({ error: 'Not allowed' });
    }

    await review.deleteOne();
    res.json({ message: 'Review deleted' });
  } catch (err) {
    next(err);
  }
});

app.post('/api/reviews/:id/react', authMiddleware, async (req, res) => {
  try {
    const { type } = req.body;
    const validTypes = ['helpful', 'funny', 'angry'];
    if (!validTypes.includes(type)) return res.status(400).json({ error: 'Invalid reaction type' });

    const review = await Review.findById(req.params.id);
    if (!review) return res.status(404).json({ error: 'Review not found' });

    const userId = req.user._id.toString();
    const alreadyReacted = review.reactions[type]?.map((u) => u.toString()).includes(userId);

    if (alreadyReacted) {
      review.reactions[type] = review.reactions[type].filter((u) => u.toString() !== userId);
    } else {
      review.reactions[type] = [...(review.reactions[type] || []), req.user._id];
    }

    await review.save();
    res.json({ message: 'Reaction updated', reactions: review.reactions });
  } catch (err) {
    res.status(500).json({ error: 'Failed to react' });
  }
});

// Admin‐only: List all reviews
app.get(
  '/api/reviews',
  authMiddleware,
  adminMiddleware,
  async (req, res, next) => {
    try {
      const allReviews = await Review.find()
        .populate('user', 'name')
        .populate('product', 'name');
      res.json(allReviews);
    } catch (err) {
      next(err);
    }
  }
);

// Admin replies to a review
app.post(
  '/api/reviews/reply/:id',
  authMiddleware,
  adminMiddleware,
  [body('reply').notEmpty().withMessage('Reply cannot be empty')],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const review = await Review.findById(req.params.id);
      if (!review) return res.status(404).json({ error: 'Review not found' });

      review.adminReply = {
        message: req.body.reply,
        date: Date.now(),
      };
      await review.save();
      res.json({ message: 'Reply added', review });
    } catch (err) {
      next(err);
    }
  }
);

app.get('/api/reactions/:productId', authMiddleware, async (req, res, next) => {
  try {
    const reviews = await Review.find({ product: req.params.productId }).lean();
    const result = {};
    for (const r of reviews) {
      const helpfulCount = r.reactions.helpful?.length || 0;
      const funnyCount = r.reactions.funny?.length || 0;
      const angryCount = r.reactions.angry?.length || 0;
      const userReactedType = r.reactions.helpful
        .map((u) => u.toString())
        .includes(req.user._id.toString())
        ? 'helpful'
        : r.reactions.funny.map((u) => u.toString()).includes(req.user._id.toString())
        ? 'funny'
        : r.reactions.angry.map((u) => u.toString()).includes(req.user._id.toString())
        ? 'angry'
        : null;

      result[r._id] = {
        helpful: helpfulCount,
        funny: funnyCount,
        angry: angryCount,
        userReactionType: userReactedType,
      };
    }
    res.json(result);
  } catch (err) {
    next(err);
  }
});

// Alternative endpoint for adding a reaction record to the Reaction model
app.post('/api/reactions', authMiddleware, async (req, res, next) => {
  try {
    const { reviewId, type } = req.body;
    if (!['helpful', 'funny', 'angry'].includes(type)) {
      return res.status(400).json({ error: 'Invalid reaction type' });
    }

    const existing = await Reaction.findOne({
      user: req.user._id,
      review: reviewId,
      type,
    });
    if (existing) {
      return res.status(400).json({ error: 'Already reacted' });
    }

    const reaction = new Reaction({ user: req.user._id, review: reviewId, type });
    await reaction.save();
    res.json({ message: 'Reaction added' });
  } catch (err) {
    next(err);
  }
});

// ────────────────────────────────────────────────────────────────────────────────
// ROUTES: CART (support guest via guestId)
// ────────────────────────────────────────────────────────────────────────────────

app.post(
  '/api/cart',
  optionalAuth,
  [
    body('productId').notEmpty().withMessage('Product ID is required'),
    body('quantity').isInt({ min: 1 }).withMessage('Quantity must be at least 1'),
  ],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { productId, quantity } = req.body;
      const product = await Product.findById(productId);
      if (!product) return res.status(400).json({ error: 'Product not found' });
      if (product.stock < quantity) return res.status(400).json({ error: 'Insufficient stock' });

      const query = getCartQuery(req);
      let cart = await Cart.findOne(query);
      if (!cart) {
        cart = new Cart({ ...query, items: [] });
      }

      const existingItemIndex = cart.items.findIndex(
        (item) => item.product.toString() === productId
      );
      if (existingItemIndex > -1) {
        cart.items[existingItemIndex].quantity += quantity;
      } else {
        cart.items.push({ product: productId, quantity });
      }
      cart.updatedAt = Date.now();
      await cart.save();

      const populatedCart = await cart.populate('items.product');
      res.json({ message: 'Cart updated', cart: populatedCart });
    } catch (error) {
      next(error);
    }
  }
);

app.get('/api/cart', optionalAuth, async (req, res, next) => {
  try {
    const query = getCartQuery(req);
    let cart = await Cart.findOne(query).populate('items.product');
    if (!cart) return res.json({ items: [] });
    res.json(cart);
  } catch (error) {
    next(error);
  }
});

app.delete('/api/cart/:productId', optionalAuth, async (req, res, next) => {
  try {
    const query = getCartQuery(req);
    const cart = await Cart.findOne(query);
    if (!cart) return res.status(404).json({ error: 'Cart not found' });

    cart.items = cart.items.filter(
      (item) => item.product.toString() !== req.params.productId
    );
    cart.updatedAt = Date.now();
    await cart.save();

    const populatedCart = await cart.populate('items.product');
    res.json({ message: 'Item removed from cart', cart: populatedCart });
  } catch (error) {
    next(error);
  }
});

// ────────────────────────────────────────────────────────────────────────────────
// ROUTES: ORDERS
// ────────────────────────────────────────────────────────────────────────────────

app.post('/api/orders', authMiddleware, async (req, res, next) => {
  try {
    const { items, shippingAddress, paymentMethod } = req.body;
    if (!items || items.length === 0)
      return res.status(400).json({ error: 'No items in order' });

    const order = new Order({
      user: req.user._id,
      items: items.map((i) => ({
        product: i.productId,
        quantity: i.quantity,
        price: i.price,
      })),
      shippingAddress,
      paymentMethod,
      total: items.reduce((acc, i) => acc + i.price * i.quantity, 0),
      status: 'pending',
    });
    await order.save();

    // Reduce stock
    for (let i of items) {
      await Product.findByIdAndUpdate(i.productId, { $inc: { stock: -i.quantity } });
    }

    res.status(201).json(order);
  } catch (err) {
    next(err);
  }
});

app.get('/api/orders/my', authMiddleware, async (req, res, next) => {
  try {
    const orders = await Order.find({ user: req.user._id }).sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    next(err);
  }
});

app.get('/api/orders/:id', authMiddleware, async (req, res, next) => {
  try {
    const order = await Order.findById(req.params.id)
      .populate('user', 'name email')
      .populate('items.product', 'name price');
    if (!order) return res.status(404).json({ error: 'Order not found' });
    res.json(order);
  } catch (err) {
    next(err);
  }
});

app.put('/api/orders/:id/pay', authMiddleware, async (req, res, next) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ error: 'Order not found' });

    order.isPaid = true;
    order.paidAt = Date.now();
    order.paymentResult = {
      id: req.body.id,
      status: req.body.status,
      update_time: req.body.update_time,
      email_address: req.body.payer.email_address,
    };
    await order.save();
    res.json(order);
  } catch (err) {
    next(err);
  }
});

app.get('/api/orders', authMiddleware, async (req, res, next) => {
  try {
    const orders = await Order.find({ user: req.user._id }).populate('items.product');
    res.json(orders);
  } catch (error) {
    next(error);
  }
});

app.put(
  '/api/orders/:orderId/cancel',
  authMiddleware,
  async (req, res, next) => {
    try {
      const order = await Order.findById(req.params.orderId);
      if (!order) return res.status(404).json({ error: 'Order not found' });
      if (order.user.toString() !== req.user._id.toString())
        return res.status(403).json({ error: 'Not authorized to cancel this order' });
      if (order.status !== 'pending')
        return res.status(400).json({ error: 'Only pending orders can be cancelled' });

      order.status = 'cancelled';
      // Restore stock
      for (const item of order.items) {
        await Product.findByIdAndUpdate(item.product, { $inc: { stock: item.quantity } });
      }
      await order.save();
      res.json({ message: 'Order cancelled', order });
    } catch (error) {
      next(error);
    }
  }
);

app.delete('/api/orders/:id', authMiddleware, async (req, res, next) => {
  try {
    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ error: 'Order not found' });
    if (order.user.toString() !== req.user._id.toString())
      return res.status(403).json({ error: 'Not authorized' });
    await order.deleteOne();
    res.json({ message: 'Order deleted' });
  } catch (err) {
    next(err);
  }
});

// ────────────────────────────────────────────────────────────────────────────────
// ADMIN: ORDERS, USER MANAGEMENT, ANALYTICS, EXPORT/IMPORT
// ────────────────────────────────────────────────────────────────────────────────

// Admin: Get All Orders (most recent first, with products)
app.get('/api/admin/orders', authMiddleware, adminMiddleware, async (req, res, next) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 20;
    const sort = { createdAt: -1 };
    const orders = await Order.find({})
      .sort(sort)
      .limit(limit)
      .populate('user', 'name email')
      .populate('items.product', 'name price')
      .lean();
    res.json(orders);
  } catch (err) {
    next(err);
  }
});

// Admin: Delete Any Order
app.delete(
  '/api/admin/orders/:id',
  authMiddleware,
  adminMiddleware,
  async (req, res, next) => {
    try {
      const order = await Order.findById(req.params.id);
      if (!order) return res.status(404).json({ error: 'Order not found' });
      await order.deleteOne();
      res.json({ message: 'Order deleted' });
    } catch (err) {
      next(err);
    }
  }
);

// Admin: Update Order Status
app.put(
  '/api/admin/orders/:orderId',
  authMiddleware,
  adminMiddleware,
  [body('status').isIn(['pending', 'completed', 'cancelled']).withMessage('Invalid status')],
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { status } = req.body;
      const order = await Order.findById(req.params.orderId);
      if (!order) return res.status(404).json({ error: 'Order not found' });

      order.status = status;
      await order.save();
      res.json({ message: 'Order status updated', order });
    } catch (error) {
      next(error);
    }
  }
);

// Admin: Export Orders as CSV
app.get(
  '/api/admin/tools/export-orders',
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const orders = await Order.find().populate('user').populate('items.product');
      const flat = orders.flatMap((order) =>
        order.items.map((item) => ({
          orderId: order._id,
          user: order.user?.email || 'N/A',
          product: item.product.name,
          qty: item.quantity,
          price: item.price,
          total: item.price * item.quantity,
          status: order.status,
          date: order.createdAt,
        }))
      );
      const csv = new Parser().parse(flat);
      res.header('Content-Type', 'text/csv');
      res.attachment('orders.csv');
      res.send(csv);
    } catch (error) {
      res.status(500).json({ error: 'Failed to export orders' });
    }
  }
);

// Admin: Import Products via CSV upload
const upload = multer({ storage: multer.memoryStorage() });
app.post(
  '/api/admin/tools/import-products',
  authMiddleware,
  adminMiddleware,
  upload.single('file'),
  async (req, res) => {
    try {
      const rows = req.file.buffer.toString().split('\n').slice(1); // skip header
      const products = rows.map((row) => {
        const [name, price, stock, category, description] = row.split(',');
        return { name, price, stock, category, description };
      });
      await Product.insertMany(products);
      res.json({ message: 'Products imported' });
    } catch (err) {
      res.status(500).json({ error: 'Failed to import products' });
    }
  }
);

// Admin: Broadcast Email to All Users
app.get('/api/admin/emails', authMiddleware, adminMiddleware, async (req, res) => {
  const users = await User.find({}, 'email');
  res.json(users.map((u) => u.email));
});

app.post('/api/admin/broadcast', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { subject, message } = req.body;
    const users = await User.find({}, 'email');
    const emails = users.map((u) => u.email);

  await transporter.sendMail({
    from: `"eStore Reports" <${process.env.EMAIL_USER}>`,
    to: process.env.ADMIN_EMAIL,
    subject: 'Subject',
    html: `<p>${message}</p>`, // <-- This is a string!
  });


    res.json({ message: 'Email broadcast sent.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to send broadcast' });
  }
});

app.post('/api/admin/tools/reset', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    await Product.deleteMany();
    await Order.deleteMany();
    await User.deleteMany({ isAdmin: false });
    res.json({ message: 'Test data reset' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reset data' });
  }
});

// ────────────────────────────────────────────────────────────────────────────────
// ADMIN ANALYTICS ROUTES
// ────────────────────────────────────────────────────────────────────────────────

app.get(
  '/api/admin/analytics/sales',
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { start, end } = req.query;
      const match = { status: 'completed' };
      if (start || end) {
        match.createdAt = {};
        if (start) match.createdAt.$gte = new Date(start);
        if (end) match.createdAt.$lte = new Date(end);
      }

      const daily = await Order.aggregate([
        { $match: match },
        {
          $group: {
            _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
            totalSales: { $sum: '$total' },
          },
        },
        { $sort: { _id: 1 } },
        {
          $project: {
            _id: 0,
            date: '$_id',
            totalSales: 1,
          },
        },
      ]);

      res.json(daily);
    } catch (error) {
      res.status(500).json({ error: 'Failed to get sales timeseries' });
    }
  }
);

app.get(
  '/api/admin/analytics/top-products',
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const { start, end } = req.query;
      const match = { status: 'completed' };
      if (start || end) {
        match.createdAt = {};
        if (start) match.createdAt.$gte = new Date(start);
        if (end) match.createdAt.$lte = new Date(end);
      }

      const topProducts = await Order.aggregate([
        { $match: match },
        { $unwind: '$items' },
        {
          $group: {
            _id: '$items.product',
            totalQuantity: { $sum: '$items.quantity' },
            totalRevenue: { $sum: { $multiply: ['$items.quantity', '$items.price'] } },
          },
        },
        {
          $lookup: {
            from: 'products',
            localField: '_id',
            foreignField: '_id',
            as: 'product',
          },
        },
        { $unwind: '$product' },
        {
          $project: {
            name: '$product.name',
            totalQuantity: 1,
            totalRevenue: 1,
          },
        },
        { $sort: { totalQuantity: -1 } },
        { $limit: 5 },
      ]);

      res.json(topProducts);
    } catch (error) {
      res.status(500).json({ error: 'Failed to get top products' });
    }
  }
);

app.get(
  '/api/admin/analytics/category-sales',
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const categorySales = await Order.aggregate([
        { $match: { status: 'completed' } },
        { $unwind: '$items' },
        {
          $lookup: {
            from: 'products',
            localField: 'items.product',
            foreignField: '_id',
            as: 'productInfo',
          },
        },
        { $unwind: '$productInfo' },
        {
          $lookup: {
            from: 'categories',
            localField: 'productInfo.category',
            foreignField: '_id',
            as: 'categoryInfo',
          },
        },
        { $unwind: '$categoryInfo' },
        {
          $group: {
            _id: '$categoryInfo.name',
            totalRevenue: { $sum: { $multiply: ['$items.price', '$items.quantity'] } },
          },
        },
        { $sort: { totalRevenue: -1 } },
      ]);

      res.json(categorySales);
    } catch (error) {
      res.status(500).json({ error: 'Failed to get category sales' });
    }
  }
);

app.get(
  '/api/admin/analytics/counts',
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const userCount = await User.countDocuments({ isAdmin: false });
      const productCount = await Product.countDocuments();
      const orderCount = await Order.countDocuments();
      const reviewCount = await Review.countDocuments();

      res.json({
        users: userCount,
        products: productCount,
        orders: orderCount,
        reviews: reviewCount,
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to get counts' });
    }
  }
);

app.get(
  '/api/admin/analytics/top-customers',
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const limit = parseInt(req.query.limit) || 5;
      const customers = await Order.aggregate([
        { $match: { status: 'completed' } },
        {
          $group: {
            _id: '$user',
            totalSpent: { $sum: '$total' },
          },
        },
        {
          $lookup: {
            from: 'users',
            localField: '_id',
            foreignField: '_id',
            as: 'userInfo',
          },
        },
        { $unwind: '$userInfo' },
        {
          $project: {
            _id: 1,
            name: '$userInfo.name',
            totalSpent: 1,
          },
        },
        { $sort: { totalSpent: -1 } },
        { $limit: limit },
      ]);

      res.json({ customers });
    } catch (error) {
      res.status(500).json({ error: 'Failed to get top customers' });
    }
  }
);

app.get(
  '/api/admin/analytics/low-stock',
  authMiddleware,
  adminMiddleware,
  async (req, res) => {
    try {
      const threshold = parseInt(req.query.threshold, 10) || 5;
      const products = await Product.find({ stock: { $lte: threshold } })
        .select('_id name stock')
        .lean();

      const results = products.map((p) => ({
        _id: p._id,
        name: p.name,
        countInStock: p.stock,
      }));

      res.json({ products: results });
    } catch (error) {
      res.status(500).json({ error: 'Failed to get low-stock products' });
    }
  }
);

// Admin User Management (toggle isAdmin, delete user)
app.put(
  '/api/users/:id',
  authMiddleware,
  adminMiddleware,
  async (req, res, next) => {
    try {
      const user = await User.findById(req.params.id);
      if (!user) return res.status(404).json({ error: 'User not found' });

      if (typeof req.body.isAdmin === 'boolean') {
        user.isAdmin = req.body.isAdmin;
      }
      await user.save();
      res.json(user);
    } catch (err) {
      next(err);
    }
  }
);

app.delete(
  '/api/users/:id',
  authMiddleware,
  adminMiddleware,
  async (req, res, next) => {
    try {
      const user = await User.findByIdAndDelete(req.params.id);
      if (!user) return res.status(404).json({ error: 'User not found' });
      res.json({ message: 'User deleted' });
    } catch (err) {
      next(err);
    }
  }
);

// GET wishlist
app.get('/api/users/wishlist', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate('wishlist');
    res.json(user.wishlist);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch wishlist' });
  }
});

// TOGGLE wishlist item
app.post('/api/users/wishlist/:productId', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    const productId = req.params.productId;

    const index = user.wishlist.findIndex((id) => id.toString() === productId);
    if (index === -1) {
      user.wishlist.push(productId);
    } else {
      user.wishlist.splice(index, 1);
    }

    await user.save();
    res.json({ message: 'Wishlist updated', wishlist: user.wishlist });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update wishlist' });
  }
});

// ────────────────────────────────────────────────────────────────────────────────
// CRON JOBS: DAILY SALES REPORT EMAIL
// ────────────────────────────────────────────────────────────────────────────────
cron.schedule('0 8 * * *', async () => {
  try {
    const totalSalesData = await Order.aggregate([
      { $match: { status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$total' } } },
    ]);

    const topProducts = await Order.aggregate([
      { $match: { status: 'completed' } },
      { $unwind: '$items' },
      {
        $group: {
          _id: '$items.product',
          totalQuantity: { $sum: '$items.quantity' },
          totalRevenue: { $sum: { $multiply: ['$items.quantity', '$items.price'] } },
        },
      },
      {
        $lookup: {
          from: 'products',
          localField: '_id',
          foreignField: '_id',
          as: 'product',
        },
      },
      { $unwind: '$product' },
      {
        $project: {
          name: '$product.name',
          totalQuantity: 1,
          totalRevenue: 1,
        },
      },
      { $sort: { totalQuantity: -1 } },
      { $limit: 5 },
    ]);

    const htmlReport = `
      <h2>📊 Daily Sales Report</h2>
      <p><strong>Total Sales:</strong> TZS ${totalSalesData[0]?.total?.toLocaleString?.() || 0}</p>
      <h3>🔥 Top Selling Products:</h3>
      <ul>
        ${topProducts
          .map(
            (p) =>
              `<li>${p.name}: ${p.totalQuantity} sold, TZS ${p.totalRevenue?.toLocaleString?.()}</li>`
          )
          .join('')}
      </ul>
    `;

    await transporter.sendMail({
      from: `"eStore Reports" <${process.env.EMAIL_USER}>`,
      to: process.env.ADMIN_EMAIL,
      subject: '📈 Daily Sales Analytics',
      html: htmlReport,
    });

    console.log('✅ Daily analytics email sent');
  } catch (error) {
    console.error('❌ Failed to send analytics email:', error.message);
  }
});

// ────────────────────────────────
// ERROR HANDLING & SERVER START
// ────────────────────────────────
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

