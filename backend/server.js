require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { MailerSend, EmailParams, Sender, Recipient } = require('mailersend');
const connectDB = require('./config/db');
const User = require('./models/User');
const OTP = require('./models/OTP');
const Transaction = require('./models/Transaction');
const authMiddleware = require('./middleware/auth');
const cors = require('cors');
const session = require('express-session');

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

app.use(cors({ origin: 'http://localhost:5173', credentials: true }));
app.use(express.json());
app.use(express.raw({ type: 'application/json' }));

// Session setup for Passport
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-session-secret',
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// MailerSend client
const mailerSend = new MailerSend({ apiKey: process.env.MAILERSEND_API_KEY });
 
// Connect to MongoDB
connectDB();

// Passport Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
            user = await User.findOne({ email: profile.emails[0].value });
            if (!user) {
                user = new User({
                    googleId: profile.id,
                    email: profile.emails[0].value,
                    password: 'google-auth-' + profile.id, // Dummy password
                    isVerified: true
                });
            } else {
                user.googleId = profile.id;
                user.isVerified = true;
            }
            await user.save();
        }
        return done(null, user);
    } catch (error) {
        return done(error, null);
    }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});

// Google auth routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        const token = jwt.sign({ userId: req.user._id }, process.env.JWT_SECRET);
        res.redirect(`http://localhost:5173/dashboard?token=${token}`);
    }
);

// Generate OTP
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

// Traditional register with OTP
app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: 'Invalid recipient email address' });
        }
        if (!emailRegex.test(process.env.MAILERSEND_SENDER_EMAIL)) {
            return res.status(500).json({ message: 'Invalid sender email address in configuration' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already in use' });
        }

        const user = new User({ email, password: hashedPassword });
        await user.save();

        const otp = generateOTP();
        const otpDoc = new OTP({ userId: user._id, otp });
        await otpDoc.save();

        console.log('Sender Email:', process.env.MAILERSEND_SENDER_EMAIL);
        console.log('Recipient Email:', email);

        const emailParams = new EmailParams()
            .setFrom(new Sender(process.env.MAILERSEND_SENDER_EMAIL, 'Payment System'))
            .setTo([new Recipient(email)])
            .setSubject('Verify Your Email - OTP')
            .setHtml(`<p>Your OTP is: <strong>${otp}</strong>. It expires in 10 minutes.</p>`);

        await mailerSend.email.send(emailParams);
        console.log(`OTP sent to ${email}: ${otp}`);

        res.status(201).json({ message: 'Registration successful. Check your email for OTP.', userId: user._id });
    } catch (error) {
        console.error('Error in registration:', error.response?.data || error);
        res.status(400).json({ message: 'Error registering user', error: error.message });
    }
});

// Verify OTP
app.post('/api/verify-otp', async (req, res) => {
    try {
        const { userId, otp } = req.body;

        const otpDoc = await OTP.findOne({ userId, otp });
        if (!otpDoc) {
            return res.status(400).json({ message: 'Invalid or expired OTP' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        user.isVerified = true;
        await user.save();
        await OTP.deleteOne({ _id: otpDoc._id });

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
        res.json({ message: 'Email verified successfully', token });
    } catch (error) {
        res.status(400).json({ message: 'Error verifying OTP', error: error.message });
    }
});

// Traditional login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        if (user.googleId && !user.password) {
            return res.status(400).json({ message: 'Please use Google login for this account' });
        }

        if (!await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        if (!user.isVerified) {
            return res.status(403).json({ message: 'Please verify your email with OTP' });
        }

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
        res.json({ token });
    } catch (error) {
        res.status(400).json({ message: 'Error logging in', error });
    }
});

// Logout
app.get('/api/logout', (req, res) => {
    req.logout(() => {
        res.json({ message: 'Logged out successfully' });
    });
});

// Create payment intent
app.post('/api/create-payment-intent', authMiddleware, async (req, res) => {
    try {
        const { amount } = req.body;
        const paymentIntent = await stripe.paymentIntents.create({
            amount: amount * 100,
            currency: 'usd',
            metadata: { userId: req.user.userId }
        });
        const transaction = new Transaction({
            userId: req.user.userId,
            amount,
            type: 'deposit',
            stripePaymentIntentId: paymentIntent.id // Must match webhook's paymentIntent.id
        });
        await transaction.save();
        console.log('Created transaction with PaymentIntent ID:', paymentIntent.id); // Debug log
        res.json({ clientSecret: paymentIntent.client_secret, transactionId: transaction._id });
    } catch (error) {
        res.status(400).json({ message: 'Payment error', error: error.message });
    }
});

// Get transactions
app.get('/api/transactions', authMiddleware, async (req, res) => {
    try {
        const transactions = await Transaction.find({ userId: req.user.userId }).sort({ createdAt: -1 });
        console.log('Sending transactions:', transactions); // Debug log
        res.json(transactions);
    } catch (error) {
        res.status(400).json({ message: 'Error fetching transactions', error: error.message });
    }
});

// Get balance
app.get('/api/balance', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        res.json({ balance: user.balance });
    } catch (error) {
        res.status(400).json({ message: 'Error fetching balance', error: error.message });
    }
});

// Webhook
app.post('/api/webhook/stripe', async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
        console.log('Webhook event received:', event.type, event.data.object.id);
    } catch (err) {
        console.error('Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }
    switch (event.type) {
        case 'payment_intent.succeeded':
            await handlePaymentSuccess(event.data.object);
            break;
        case 'payment_intent.payment_failed':
            await handlePaymentFailure(event.data.object);
            break;
        default:
            console.log(`Unhandled event type ${event.type}`);
    }
    res.status(200).json({ received: true });
});

async function handlePaymentSuccess(paymentIntent) {
    const transaction = await Transaction.findOne({ stripePaymentIntentId: paymentIntent.id });
    console.log('Found transaction:', transaction);
    if (transaction && transaction.status !== 'completed') {
        transaction.status = 'completed';
        await transaction.save();
        console.log('Transaction updated to completed:', transaction._id);
        const user = await User.findById(transaction.userId);
        if (user) {
            user.balance += transaction.amount;
            await user.save();
            console.log('User balance updated:', user.balance);
        }
    } else {
        console.log('Transaction not updated:', transaction ? 'Already completed' : 'Not found');
    }
}
async function handlePaymentFailure(paymentIntent) {
    const transaction = await Transaction.findOne({ stripePaymentIntentId: paymentIntent.id });
    if (transaction && transaction.status === 'pending') {
        transaction.status = 'failed';
        await transaction.save();
    }
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));