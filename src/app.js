const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const dotenv = require("dotenv");
const errorHandler = require("./middlewares/errorHandler");
const v1Routes = require("./routes/v1");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const Limiter = require("./middlewares/rateLimiter");
 const adminRoutes = require("./routes/admin/adminAuthRoutes");
dotenv.config();

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

app.use(Limiter);

app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Welcome to Nimmoh Agency Banking Admin API",
  });
});

// Versioned routes
app.use("/api/v1", v1Routes);
 app.use('/api/v1/admin', adminRoutes);

app.use((err, req, res, next) => {
  res.status(500).json({
    success: false,
    message: err.message,
  });
});
// Error handler
app.use(errorHandler);

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Finexa API is running on port ${PORT}`);
});

module.exports = app;
