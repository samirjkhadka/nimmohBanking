const jwt = require("jsonwebtoken");
const config = require("../config/config");
const { verifyToken, verifyAccessToken } = require("../utils/jwt");
const { error } = require("../utils/response");

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res
      .status(401)
      .json({ success: false, message: "Access token is missing" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const user = verifyToken(token);
    req.user = user;
    next();
  } catch (err) {
    return res.status(403).json({ success: false, message: "Invalid token" });
  }
}

function verifyAdminToken  (req, res, next)  {
  const authHeader = req.headers.authorization || req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return error(res, "UnAuthorised. Access token is missing", 401);
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = verifyAccessToken(token);
    req.admin = decoded;
    
    next();
  } catch (err) {
    return error(res, "UnAuthorised. Invalid or expired token", 401);
  }
};

module.exports = {authenticateToken, verifyAdminToken};
