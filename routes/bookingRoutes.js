const express = require("express");
const bookingController = require("../controllers/bookingController");
const authController = require("../controllers/authController");

const router = express.Router();

router.use(authController.protect);

router.post("/", bookingController.createBooking);
router.get("/me", bookingController.getUserBookings);
router.patch("/:id/cancel", bookingController.cancelBooking);

module.exports = router;
