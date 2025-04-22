const fs = require("fs");
const { platform } = require("os");
const path = require("path");

function requestLogger(req, res, next) {
  const log = {
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    platform: req.headers["user-agent"] || "",
    timestamp: new Date().toISOString(),
  };

  fs.appendFileSync(
    path.join(__dirname, "../logs/requests.log"),
    JSON.stringify(log) + "\n"
  );
  next();
}

module.exports = requestLogger;
