const Review = require("../models/reviewModel");
const catchAsync = require("../utils/catchAsync");
const mongoose = require("mongoose");

// Add review
exports.addReview = catchAsync(async (req, res, next) => {
  console.log("req.body", req.body);
  const { userId, carId, rating, comment, title } = req.body;
  const review = await Review.create({
    user: userId,
    car: carId,
    rating,
    comment,
    title,
  });
  console.res.status(201).json({ status: "success", data: review });
});

// Get reviews for a car
exports.getCarReviews = catchAsync(async (req, res, next) => {
  console.log("req.params.is", req.params);
  const carId = new mongoose.Types.ObjectId(req.params.id);
  const reviews = await Review.find({ car: carId }).populate(
    "user",
    "fullName avatar"
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
