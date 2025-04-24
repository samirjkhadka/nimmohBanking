const {
  findByUsernameOrEmail,
  saveOTPSecret,
  getAdminById,
} = require("../../models/admin/adminUserModel");
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../../utils/jwt");
const {
  generateSecret,
  verifyTOTPToken,
  generateQRCode,
} = require("../../utils/otp");
const { comparePassword } = require("../../utils/password");
const { error, success } = require("../../utils/response");
const qrCode = require("qrcode");

exports.login = async (req, res) => {
  if (!req.body) {
    return error(res, "Invalid request. Request body is required", 400);
  }

  const { usernameOrEmail, password } = req.body;

  if (!usernameOrEmail || !password) {
    return error(
      res,
      "Invalid request. usernameOrEmail and password are required",
      400
    );
  }

  try {
    const user = await findByUsernameOrEmail(usernameOrEmail);
    console.log(user);
    if (!user) {
      return error(res, "Invalid credentials", 401);
    }
    if (!user.is_active) {
      return error(res, "Account is inactive", 403);
    }

    const isMatch = await comparePassword(password, user.password);
    if (!isMatch) {
      return error(res, "Invalid credentials", 401);
    }

    //2FA check
    if (!user.otp_secret) {
      const secret = generateSecret(`Finexa 2FA - ${user.username}`);

      await saveOTPSecret(user.id, secret.base32);

      const otpauthURL = secret.otpauth_url;
      const qrCodeDataUrl = await qrCode.toDataURL(otpauthURL);

      return success(
        res,
        "2FA Setup required",
        { userId: user.id, qrCodeDataUrl, secret: secret.base32 },
        206
      );
    }
    if (user.is_2fa_enabled) {
      return success(
        res,
        "2FA verification required",

        { userId: user.id },
        200
      );
    }
  } catch (err) {
    console.error(err);
    return error(res, "Something went wrong", 500);
  }
};

exports.verify2FA = async (req, res) => {
  if (!req.body) {
    return error(res, "Invalid request. Request body is required", 400);
  }
  try {
    const { userId, token } = req.body;

    if (!userId || !token) {
      return error(res, "Invalid request. User Id and token are required", 400);
    }

    const user = await getAdminById(userId);
    console.log(user);
    if (!user || !user.is_2fa_enabled || !user.two_fa_secret) {
      return error(res, "2FA not enabled or invalid user", 400);
    }
    const isValid = verifyTOTPToken(user.two_fa_secret, token);

    if (!isValid) {
      return error(res, "Invalid 2FA token", 400);
    }
    const accesstoken = generateAccessToken(user);
    const refereshToken = generateRefreshToken(user);

    return success(res, "2FA verified", { accesstoken, refereshToken }, 200);
  } catch (err) {
    console.error(err);
    return error(res, "Something went wrong", 500);
  }
};

exports.setup2FA = async (req, res) => {
  if (!req.body) {
    return error(res, "Invalid request. Request body is required", 400);
  }
  try {
    const { userId } = req.body;

    if (!userId) {
      return error(res, "Invalid request. User Id is required", 400);
    }

    const user = await getAdminById(userId);

    if (!user || !user.is_2fa_enabled || !user.two_fa_secret) {
      return error(res, "2FA not enabled or invalid user", 400);
    }

    const secret = generateSecret(`Finexa 2FA - ${user.username}`);
    const qrCode = await generateQRCode(secret);

    await saveOTPSecret(user.id, secret.base32);

    return success(
      res,
      "2FA Setup successful",
      { qrCode, secret: secret.base32 },
      200
    );
  } catch (err) {
    console.error(err);
    return error(res, "Something went wrong", 500);
  }
};
