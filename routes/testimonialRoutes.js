const express = require("express");
const router = express.Router();
const testimonialController = require("../controllers/testimonialController");
const { protect, restrictTo } = require("../middleware/authMiddleware");

// Public: view approved testimonials
router.get("/", testimonialController.getTestimonials);

// Authenticated user: add testimonial
router.post("/", protect, testimonialController.addTestimonial);

// User: update their testimonial
router.put("/:id", protect, testimonialController.updateTestimonial);

// User/Admin: delete testimonial
router.delete("/:id", protect, testimonialController.deleteTestimonial);

// Admin: approve testimonial
router.patch(
  "/:id/approve",
  protect,
  restrictTo("admin"),
  testimonialController.approveTestimonial
);

module.exports = router;
