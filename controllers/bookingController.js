const Booking = require("../models/bookingModel");
const catchAsync = require("../utils/catchAsync");

// Create booking
exports.createBooking = catchAsync(async (req, res, next) => {
  const booking = await Booking.create({ ...req.body, user: req.user.id });
  res.status(201).json({ status: "success", data: booking });
});

// Get my bookings
exports.getMyBookings = catchAsync(async (req, res, next) => {
  const bookings = await Booking.find({ user: req.user.id }).populate("car");
  res.json({ status: "success", results: bookings.length, data: bookings });
});

// Update booking status
exports.updateBookingStatus = catchAsync(async (req, res, next) => {
  const booking = await Booking.findByIdAndUpdate(
    req.params.id,
    { status: req.body.status },
    { new: true }
  );
  res.json({ status: "success", data: booking });
});
exports.updateBookingStatus = catchAsync(async (req, res, next) => {
  const booking = await Booking.findByIdAndUpdate(
    req.params.id,
    { status: req.body.status },
    { new: true }
  );
  res.json({ status: "success", data: booking });
});

// Get all bookings
exports.getAllBookings = catchAsync(async (req, res, next) => {
  const bookings = await Booking.find();
  res.json({ status: "success", results: bookings.length, data: bookings });
});
exports.getUserBookings = catchAsync(async (req, res, next) => {
  const bookings = await Booking.find({ user: req.user.id });
  res.json({ status: "success", results: bookings.length, data: bookings });
});
exports.cancelBooking = catchAsync(async (req, res, next) => {
  const booking = await Booking.findByIdAndUpdate(
    req.params.id,
    { status: "cancelled" },
    { new: true }
  );
  res.json({ status: "success", data: booking });
});
