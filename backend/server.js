require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');
const nodemailer = require('nodemailer');
const connectDB = require('./config/db');
const User = require('./models/User');
const Transaction = require('./models/Transaction');
const OTP = require('./models/OTP');
const authMiddleware = require('./middleware/auth');
const cors = require('cors');

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

app.use(cors({ origin: 'http://localhost:5173', credentials: true }));
app.use(express.json());
app.use(express.raw({ type: 'application/json' }));

// Email transporter setup (using Gmail as an example)
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS // Use App Password if 2FA is enabled
    }
});

// Connect to MongoDB
connectDB();

// Generate OTP
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
};

// Register user with OTP
app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({ email, password: hashedPassword });
        await user.save();

        // Generate and save OTP
        const otp = generateOTP();
        const otpDoc = new OTP({ userId: user._id, otp });
        await otpDoc.save();

        // Send OTP email
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Your OTP for Email Verification',
            text: `Your OTP is: ${otp}. It expires in 10 minutes.`
        });

        res.status(201).json({ message: 'Registration successful. Please check your email for the OTP.', userId: user._id });
    } catch (error) {
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

// Login with verification check
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        if (!user.isVerified) {
            return res.status(403).json({ message: 'Please verify your email with the OTP sent to you' });
        }

        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET);
        res.json({ token });
    } catch (error) {
        res.status(400).json({ message: 'Error logging in', error });
    }
});

app.post('/api/resend-otp', async (req, res) => {
    try {
        const { userId } = req.body;
        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ message: 'User not found' });
        if (user.isVerified) return res.status(400).json({ message: 'Email already verified' });

        await OTP.deleteMany({ userId }); // Remove old OTPs
        const otp = generateOTP();
        const otpDoc = new OTP({ userId, otp });
        await otpDoc.save();

        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Your New OTP for Email Verification',
            text: `Your new OTP is: ${otp}. It expires in 10 minutes.`
        });

        res.json({ message: 'New OTP sent to your email' });
    } catch (error) {
        res.status(400).json({ message: 'Error resending OTP', error: error.message });
    }
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