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

function generateAccessToken(payload) {
  return jwt.sign(payload, JWT.secret, { expiresIn: JWT.expiresIn });
}

function generateRefreshToken(payload) {
  return jwt.sign(payload, JWT.refreshSecret, {
    expiresIn: JWT.refreshExpiresIn,
  });
}

function verifyAccessToken(token) {
  return jwt.verify(token, JWT.secret);
}

function verifyRefreshToken(token) {
  return jwt.verify(token, JWT.refreshSecret);
}

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyToken,
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
};
