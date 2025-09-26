const mongoose = require("mongoose");

const testimonialSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    message: {
      type: String,
      required: true,
      trim: true,
      maxlength: 1000, // prevent spammy long texts
    },
    rating: {
      type: Number,
      min: 1,
      max: 5,
      required: true,
    },
    approved: {
      type: Boolean,
      default: false, // admin can moderate before showing on frontend
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Testimonial", testimonialSchema);
