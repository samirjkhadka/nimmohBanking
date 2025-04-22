const jwt = require("jsonwebtoken");
const { JWT } = require("../config/config");

function generateAccessToken(payload) {
  return jwt.sign(payload, JWT.secret, { expiresIn: JWT.expiresIn });
}

function generateRefreshToken(payload) {
  return jwt.sign(payload, JWT.refreshSecret, {
    expiresIn: JWT.refreshExpiresIn,
  });
}

function verifyToken(token, isRefresh = false) {
  return jwt.verify(token, isRefresh ? JWT.refreshSecret : JWT.secret);
}

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyToken,
};
