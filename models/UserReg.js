const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    UserId: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

module.exports = mongoose.model('UserReg', userSchema);
