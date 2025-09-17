const Car = require("../models/carModel");
const catchAsync = require("../utils/catchAsync");

// Add a new car
exports.createCar = catchAsync(async (req, res, next) => {
  const car = await Car.create(req.body);
  res.status(201).json({ status: "success", data: car });
});

// Get all available cars
exports.getAvailableCars = catchAsync(async (req, res, next) => {
  const cars = await Car.find({ available: true });
  res.json({ status: "success", results: cars.length, data: cars });
});

// Update car availability
exports.updateCar = catchAsync(async (req, res, next) => {
  const car = await Car.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  });
  res.json({ status: "success", data: car });
});
exports.updateCar = catchAsync(async (req, res, next) => {
  const car = await Car.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  });
  res.json({ status: "success", data: car });
});
exports.deleteCar = catchAsync(async (req, res, next) => {
  const car = await Car.findByIdAndDelete(req.params.id);
  res.json({ status: "success", data: car });
});
exports.getAllCars = catchAsync(async (req, res, next) => {
  const cars = await Car.find();
  res.json({ status: "success", results: cars.length, data: cars });
});
exports.getCar = catchAsync(async (req, res, next) => {
  const car = await Car.findById(req.params.id);
  res.json({ status: "success", data: car });
});
