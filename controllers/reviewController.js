const Review = require("../models/reviewModel");
const catchAsync = require("../utils/catchAsync");

// Add review
exports.addReview = catchAsync(async (req, res, next) => {
  const review = await Review.create({
    ...req.body,
    user: req.user.id,
    booking: req.params.bookingId,
  });
  res.status(201).json({ status: "success", data: review });
});

// Get reviews for a car
exports.getCarReviews = catchAsync(async (req, res, next) => {
  const reviews = await Review.find({ car: req.params.carId }).populate(
    "user",
    "fullName"
  );
  res.json({ status: "success", results: reviews.length, data: reviews });
});
exports.createReview = catchAsync(async (req, res, next) => {
  const review = await Review.create({
    ...req.body,
    user: req.user.id,
    car: req.params.carId,
  });
  res.status(201).json({ status: "success", data: review });
});
