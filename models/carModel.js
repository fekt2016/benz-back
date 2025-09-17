const mongoose = require("mongoose");

const carSchema = new mongoose.Schema(
  {
    series: {
      type: String,
      enum: [
        "A-Class",
        "B-Class",
        "C-Class",
        "E-Class",
        "S-Class",
        "CLA",
        "CLS",
        "GLA",
        "GLB",
        "GLC",
        "GLE",
        "GLS",
        "G-Class",
        "EQC", // Electric
        "AMG GT",
      ],
      required: true,
    },
    model: { type: String, required: true }, // e.g., "C300", "GLE 350d", "AMG GT R"
    year: { type: Number, required: true },
    pricePerDay: { type: Number, required: true },
    transmission: {
      type: String,
      enum: ["manual", "automatic"],
      default: "automatic",
    },
    fuelType: {
      type: String,
      enum: ["petrol", "diesel", "electric", "hybrid"],
      default: "petrol",
    },
    seats: { type: Number, default: 4 },
    images: [String], // URLs or Cloudinary links
    available: { type: Boolean, default: true },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Car", carSchema);
