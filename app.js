const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const AppError = require("./utils/appError"); // make sure this exists
const globalErrorHandler = require("./controllers/errorController");
// Routers
// const newsletterRouter = require("./routes/newsletterRoutes");
const routers = {
  payment: require("./routes/paymentRoutes"),
  user: require("./routes/userRoutes"),
  car: require("./routes/carRoutes"),
  driver: require("./routes/driverRoutes"),
  notification: require("./routes/notificationRoutes"),
  review: require("./routes/reviewRoutes"),
  booking: require("./routes/bookingRoutes"),
  auth: require("./routes/authRoutes"),
};
const app = express();

// Environment
const isDevelopment = process.env.NODE_ENV === "development";
const isProduction = process.env.NODE_ENV === "production";

// CORS origins
const allowedOrigins = [
  "https://eazworld.com",
  "https://www.eazworld.com",
  "https://api.eazworld.com",
  process.env.FRONTEND_URL,
].filter(Boolean);

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (isDevelopment) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error(`CORS not allowed for origin: ${origin}`), false);
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-User-Role",
    "x-seller-subdomain",
    "x-admin-subdomain",
  ],
  exposedHeaders: ["Content-Range", "X-Total-Count"],
};

// Middlewares
app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://cdnjs.cloudflare.com",
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com",
          "https://cdnjs.cloudflare.com",
        ],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "https://res.cloudinary.com"],
        connectSrc: ["'self'", "https://api.cloudinary.com"],
      },
    },
  })
);

if (isDevelopment) {
  app.use(morgan("dev"));
} else {
  app.use(
    morgan("combined", {
      skip: (req, res) => res.statusCode < 400,
      stream: process.stderr,
    })
  );
  app.use(
    morgan("combined", {
      skip: (req, res) => res.statusCode >= 400,
      stream: process.stdout,
    })
  );
}

app.set("trust proxy", 1);

app.use(
  express.json({
    limit: isProduction ? "10mb" : "50mb",
    verify: (req, res, buf) => {
      try {
        JSON.parse(buf);
      } catch (e) {
        throw new AppError("Invalid JSON payload", 400);
      }
    },
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: isProduction ? "10mb" : "50mb",
    parameterLimit: isProduction ? 100 : 1000,
  })
);

app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();

  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains; preload"
  );
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.removeHeader("X-Powered-By");

  next();
});

// Routes
app.use("/api/v1/payments", routers.payment);
app.use("/api/v1/users", routers.user);
app.use("/api/v1/cars", routers.car);
app.use("/api/v1/drivers", routers.driver);
app.use("/api/v1/notifications", routers.notification);
app.use("/api/v1/reviews", routers.review);
app.use("/api/v1/bookings", routers.booking);
app.use("/api/v1/auth", routers.auth);

app.use(globalErrorHandler);

module.exports = app;
