const dotenv = require("dotenv");

dotenv.config();

module.exports = {
  PORT: process.env.PORT || 5000,
  DB: {
    URL: process.env.DATABASE_URL,
  },
  JWT: {
    secret: process.env.JWT_SECRET,
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    expiresIn: process.env.TOKEN_EXPIRY,
    refreshExpiresIn: process.env.REFRESH_TOKEN_EXPIRY,
  },
  EMAIL: {
    from: process.env.EMAIL_FROM,
    nodemailerUser: process.env.SMTP_USER,
    nodemailerPass: process.env.SMTP_PASS,
    service: process.env.SMTP_SERVICE,
    port: process.env.SMTP_PORT,
    secure: process.env.SMTP_SECURE === "true",
    tls: { rejectUnauthorized: false },
    host: process.env.SMTP_HOST,
  },
  OTP: {
    window: process.env.OTP_WINDOW,
  },
  SECURITY: {
    lockoutThreshold: 3,
    passwordHistoryCount: 3,
  },
};
