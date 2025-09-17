const Driver = require("../models/driverModel");
const catchAsync = require("../utils/catchAsync");

// Add additional driver
exports.addDriver = catchAsync(async (req, res, next) => {
  const driver = await Driver.create({ ...req.body, user: req.user.id });
  res.status(201).json({ status: "success", data: driver });
});

// Verify driver license (admin or system)
exports.verifyDriver = catchAsync(async (req, res, next) => {
  const driver = await Driver.findByIdAndUpdate(
    req.params.id,
    { verified: true },
    { new: true }
  );
  res.json({ status: "success", data: driver });
});
exports.verifyDriverLicense = catchAsync(async (req, res, next) => {
  const driver = await Driver.findByIdAndUpdate(
    req.params.id,
    { verified: true },
    { new: true }
  );
  res.json({ status: "success", data: driver });
});

// Get all drivers
exports.getAllDrivers = catchAsync(async (req, res, next) => {
  const drivers = await Driver.find();
  res.json({ status: "success", results: drivers.length, data: drivers });
});

// Get driver by ID
exports.getDriver = catchAsync(async (req, res, next) => {
  const driver = await Driver.findById(req.params.id);
  res.json({ status: "success", data: driver });
});

// Update driver
exports.updateDriver = catchAsync(async (req, res, next) => {
  const driver = await Driver.findByIdAndUpdate(req.params.id, req.body, {
    new: true,
  });
  res.json({ status: "success", data: driver });
});
