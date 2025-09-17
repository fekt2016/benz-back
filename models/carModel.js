const mongoose = require("mongoose");

const carSchema = new mongoose.Schema(
  {
    make: { type: String, required: true },
    model: { type: String, required: true },
    year: { type: Number, required: true },
    pricePerDay: { type: Number, required: true },
    transmission: { type: String, enum: ["manual", "automatic"] },
    fuelType: {
      type: String,
      enum: ["petrol", "diesel", "electric", "hybrid"],
    },
    seats: { type: Number },
    images: [String],
    available: { type: Boolean, default: true },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Car", carSchema);
