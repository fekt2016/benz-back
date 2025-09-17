const express = require("express");
const carController = require("../controllers/carController");
const authController = require("../controllers/authController");

const router = express.Router();

router
  .route("/")
  .get(carController.getAllCars)
  .post(
    authController.protect,
    authController.restrictTo("admin"),
    carController.createCar
  );

router
  .route("/:id")
  .get(carController.getCar)
  .patch(
    authController.protect,
    authController.restrictTo("admin"),
    carController.updateCar
  )
  .delete(
    authController.protect,
    authController.restrictTo("admin"),
    carController.deleteCar
  );

module.exports = router;
