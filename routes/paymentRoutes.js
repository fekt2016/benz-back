const express = require("express");
const paymentController = require("../controllers/paymentController");
const authController = require("../controllers/authController");

const router = express.Router();

// All routes require authentication
router.use(authController.protect);

// Create a new payment intent/session
router.post("/create", paymentController.createPayment);

// Confirm a payment (webhook or callback)
router.post("/confirm", paymentController.confirmPayment);

// Refund a payment
router.post("/:id/refund", paymentController.refundPayment);

// Get all payments for logged-in user
router.get("/my-payments", paymentController.getMyPayments);

// Admin: get all payments
router.get("/", paymentController.getAllPayments);

// Admin: get single payment
router.get("/:id", paymentController.getPaymentById);

module.exports = router;
