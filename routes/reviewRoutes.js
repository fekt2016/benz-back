const express = require("express");
const reviewController = require("../controllers/reviewController");
const authController = require("../controllers/authController");

const router = express.Router({ mergeParams: true });

router.use(authController.protect);

router.post("/:carId", reviewController.createReview);
router.get("/:carId", reviewController.getCarReviews);

module.exports = router;
