const express = require("express");
const reviewController = require("../controllers/reviewController");
const authController = require("../controllers/authController");

const router = express.Router({ mergeParams: true });

router.post(
  "/",
  authController.protect,
  authController.restrictTo("user"),
  reviewController.addReview
);
router.get("/car/:id", reviewController.getCarReviews);
module.exports = router;
