const Notification = require("../models/notificationModel");
const catchAsync = require("../utils/catchAsync");

// Send notification
exports.sendNotification = catchAsync(async (req, res, next) => {
  const notification = await Notification.create({
    ...req.body,
    user: req.user.id,
  });
  res.status(201).json({ status: "success", data: notification });
});

// Get my notifications
exports.getMyNotifications = catchAsync(async (req, res, next) => {
  const notifications = await Notification.find({ user: req.user.id });
  res.json({ status: "success", data: notifications });
});

// Mark notification as read
exports.markAsRead = catchAsync(async (req, res, next) => {
  const notification = await Notification.findByIdAndUpdate(
    req.params.id,
    { read: true },
    { new: true }
  );
  res.json({ status: "success", data: notification });
});
exports.getUserNotifications = catchAsync(async (req, res, next) => {
  const notifications = await Notification.find({ user: req.user.id });
  res.json({ status: "success", data: notifications });
});
