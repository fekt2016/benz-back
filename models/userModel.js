const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const userSchema = new mongoose.Schema(
  {
    fullName: { type: String, required: true, trim: true },
    phone: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, minlength: 6, select: false },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
    otp: { type: String },
    otpExpires: { type: Date },
    // License info
    licenseNumber: { type: String },
    licenseImage: { type: String }, // Cloudinary URL
    licenseVerified: { type: Boolean, default: false },
  },
  { timestamps: true }
);

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});
userSchema.methods.createOtp = function () {
  const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit
  this.otp = otp;
  this.otpExpires = Date.now() + 10 * 60 * 1000; // valid for 10 minutes
  return otp; // return so you can send via SMS
};
// Password comparison
userSchema.methods.correctPassword = async function (candidate, hashed) {
  return bcrypt.compare(candidate, hashed);
};
userSchema.methods.createOtp = function () {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  // Hash the OTP before saving
  this.otp = crypto.createHash("sha256").update(otp).digest("hex");
  this.otpExpires = Date.now() + 10 * 60 * 1000; // 10 min
  return otp; // Return raw OTP to send via SMS
};
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );

    return JWTTimestamp < changedTimestamp;
  }
  return false;
};

// Method to check OTP
userSchema.methods.verifyOtp = function (enteredOtp) {
  const hashedOtp = crypto
    .createHash("sha256")
    .update(enteredOtp)
    .digest("hex");

  return this.otp === hashedOtp && this.otpExpires > Date.now();
};
module.exports = mongoose.model("User", userSchema);
