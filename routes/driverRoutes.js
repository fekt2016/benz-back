const express = require("express");
const driverController = require("../controllers/driverController");
const authController = require("../controllers/authController");

const router = express.Router();

router.use(authController.protect);

router.post("/", driverController.addDriver);
router.patch(
  "/:id/verify",
  authController.restrictTo("admin"),
  driverController.verifyDriverLicense
);

module.exports = router;
