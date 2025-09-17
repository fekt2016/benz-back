const Car = require("../models/carModel");
const catchAsync = require("../utils/catchAsync");

// Add a new car
// Create a new Benz car
exports.createCar = catchAsync(async (req, res, next) => {
  const { series, model, year, pricePerDay, transmission, fuelType, seats } =
    req.body;

  // Validate series
  if (!BENZ_SERIES.includes(series)) {
    return res.status(400).json({
      status: "fail",
      message: `Invalid Mercedes-Benz series. Allowed: ${BENZ_SERIES.join(
        ", "
      )}`,
    });
  }

  const car = await Car.create({
    series,
    model,
    year,
    pricePerDay,
    transmission,
    fuelType,
    seats,
    images: req.body.images || [],
  });

  res.status(201).json({ status: "success", data: car });
});

exports.getAvailableCars = catchAsync(async (req, res, next) => {
  const filter = { available: true };

  if (req.query.series) {
    filter.series = req.query.series;
  }
  if (req.query.model) {
    filter.model = req.query.model;
  }

  const cars = await Car.find(filter);
  res.json({ status: "success", results: cars.length, data: cars });
});
// Get a single car by ID
exports.getCar = catchAsync(async (req, res, next) => {
  const car = await Car.findById(req.params.id);
  if (!car) {
    return res.status(404).json({ status: "fail", message: "Car not found" });
  }
  res.json({ status: "success", data: car });
});

// Get all cars (admin view)
exports.getAllCars = catchAsync(async (req, res, next) => {
  const cars = await Car.find();
  res.json({ status: "success", results: cars.length, data: cars });
});

// Update a car
exports.updateCar = catchAsync(async (req, res, next) => {
  const updates = req.body;

  if (updates.series && !BENZ_SERIES.includes(updates.series)) {
    return res.status(400).json({
      status: "fail",
      message: `Invalid Mercedes-Benz series. Allowed: ${BENZ_SERIES.join(
        ", "
      )}`,
    });
  }

  const car = await Car.findByIdAndUpdate(req.params.id, updates, {
    new: true,
    runValidators: true,
  });

  if (!car) {
    return res.status(404).json({ status: "fail", message: "Car not found" });
  }

  res.json({ status: "success", data: car });
});

// Delete a car
exports.deleteCar = catchAsync(async (req, res, next) => {
  const car = await Car.findByIdAndDelete(req.params.id);
  if (!car) {
    return res.status(404).json({ status: "fail", message: "Car not found" });
  }
  res.json({ status: "success", data: null });
});

// Get cars by series
exports.getCarsBySeries = catchAsync(async (req, res, next) => {
  const cars = await Car.find({ series: req.params.series });
  res.json({ status: "success", results: cars.length, data: cars });
});
