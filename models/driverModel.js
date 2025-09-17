const mongoose = require("mongoose");

const driverSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    fullName: { type: String, required: true, trim: true },
    phone: { type: String, required: true },
    licenseNumber: { type: String, required: true },
    licenseImage: { type: String },
    verified: { type: Boolean, default: false },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Driver", driverSchema);
