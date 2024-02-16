const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['Admin', 'Supervisor', 'Worker'], default: 'Worker' },
  adminProvidedPassword: { type: Boolean, default: false }
});

const usermodel = new mongoose.model("usermodel",userSchema)
module.exports = {usermodel}