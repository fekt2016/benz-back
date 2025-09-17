const mongoose = require("mongoose");

const reviewSchema = new mongoose.Schema(
  {
    booking: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Booking",
      required: true,
    },
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    car: { type: mongoose.Schema.Types.ObjectId, ref: "Car", required: true },

    rating: { type: Number, min: 1, max: 5, required: true },
    comment: { type: String, trim: true },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Review", reviewSchema);
