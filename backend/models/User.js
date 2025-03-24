const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    googleId: { type: String, unique: true, sparse: true }, // For Google users
    email: { type: String, required: true, unique: true },
    password: { type: String }, // Optional for Google users
    balance: { type: Number, default: 0 },
    isVerified: { type: Boolean, default: false } // True for Google users by default
});

module.exports = mongoose.model('User', userSchema);