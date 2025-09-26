const Car = require("../models/carModel");
const catchAsync = require("../utils/catchAsync");
const fs = require("fs");

// Add a new car
// Create a new Benz car
exports.createCar = catchAsync(async (req, res, next) => {
  console.log("body", req.body);
  const { series, model, year, pricePerDay, transmission, fuelType, seats } =
    req.body;

  const cloudinary = req.app.get("cloudinary");
  let imageUrls = [];
  if (req.body.images && req.body.images.length > 0) {
    const uploadPromises = req.body.images.map(async (filePath) => {
      const result = await cloudinary.uploader.upload(filePath, {
        folder: "cars",
      });

      return result.secure_url;
    });

    imageUrls = await Promise.all(uploadPromises);
  }
  console.log("imageUrls", imageUrls);
  const car = await Car.create({
    series,
    model,
    year,
    pricePerDay,
    transmission,
    fuelType,
    seats,
    images: imageUrls,
  });

  res.status(201).json({ status: "success", data: car });
});

// exports.getCars = catchAsync(async (req, res, next) => {
//   console.log("req.query", req.query);
//   // If a query param is provided, filter by it
//   const { status } = req.query;

//   let filter = {};
//   if (status) {
//     // Only allow valid statuses
//     const validStatuses = ["available", "maintenance", "rented"];
//     if (validStatuses.includes(status)) {
//       filter.status = status;
//     } else {
//       return next(
//         new AppError(
//           "Invalid status. Use available, maintenance, or rented.",
//           400
//         )
//       );
//     }
//   }

//   const cars = await Car.find(filter);

//   res.status(200).json({
//     status: "success",
//     results: cars.length,
//     data: cars,
//   });
// });

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
  console.log("updates", updates);

  // if (updates.series && !BENZ_SERIES.includes(updates.series)) {
  //   return res.status(400).json({
  //     status: "fail",
  //     message: `Invalid Mercedes-Benz series. Allowed: ${BENZ_SERIES.join(
  //       ", "
  //     )}`,
  //   });
  // }

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
