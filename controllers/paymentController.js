const Payment = require("../models/paymentModel");
const catchAsync = require("../utils/catchAsync");

// Create payment
exports.createPayment = catchAsync(async (req, res, next) => {
  const payment = await Payment.create(req.body);
  res.status(201).json({ status: "success", data: payment });
});

// Get payments for booking
exports.getPaymentsByBooking = catchAsync(async (req, res, next) => {
  const payments = await Payment.find({ booking: req.params.bookingId });
  res.json({ status: "success", data: payments });
});

exports.confirmPayment = catchAsync(async (req, res, next) => {
  const payment = await Payment.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  });
  res.json({ status: "success", data: payment });
});
exports.refundPayment = catchAsync(async (req, res, next) => {
  const payment = await Payment.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  });
  res.json({ status: "success", data: payment });
});
exports.getMyPayments = catchAsync(async (req, res, next) => {
  const payments = await Payment.find({ user: req.user.id });
  res.json({ status: "success", data: payments });
});
exports.getAllPayments = catchAsync(async (req, res, next) => {
  const payments = await Payment.find();
  res.json({ status: "success", data: payments });
});

exports.getPaymentById = catchAsync(async (req, res, next) => {
  const payment = await Payment.findById(req.params.id);
  res.json({ status: "success", data: payment });
});
