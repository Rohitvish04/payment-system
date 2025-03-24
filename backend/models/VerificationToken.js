const mongoose = require('mongoose');

const verificationTokenSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    token: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: '24h' } // Token expires in 24 hours
});

module.exports = mongoose.model('VerificationToken', verificationTokenSchema);