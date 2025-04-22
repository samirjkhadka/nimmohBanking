const speakeasy = require("speakeasy");
const { OTP } = require("../config/config");

function generateSecret(label = "Finexa 2FA") {
  return speakeasy.generateSecret({ length: 20, name: label }); // 20 bytes
}

function getOTPToken(secret) {
  return speakeasy.totp({
    secret: secret.base32,
    encoding: "base32",
    digits: 6,
  });
}

function verifyTOTPToken(secret, token) {
  return speakeasy.totp.verify({
    secret: secret,
    encoding: "base32",
    token,
    window: OTP.window,
  });
}

module.exports = {
  generateSecret,
  getOTPToken,
  verifyTOTPToken,
};
