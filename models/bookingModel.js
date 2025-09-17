const mongoose = require("mongoose");

const bookingSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    car: { type: mongoose.Schema.Types.ObjectId, ref: "Car", required: true },

    startDate: { type: Date, required: true },
    endDate: { type: Date, required: true },
    totalPrice: { type: Number, required: true },

    status: {
      type: String,
      enum: ["pending", "confirmed", "cancelled", "completed"],
      default: "pending",
    },

    insurance: {
      provider: String,
      policyNumber: String,
      verified: { type: Boolean, default: false },
    },

    additionalDrivers: [
      { type: mongoose.Schema.Types.ObjectId, ref: "Driver" },
    ],

    payment: { type: mongoose.Schema.Types.ObjectId, ref: "Payment" },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Booking", bookingSchema);
