const { deleteRefreshToken } = require("../../models/admin/refreshTokenModel");
const {
  findByUsernameOrEmail,
  saveOTPSecret,
  getAdminById,
  updateAdminPassword,
  savePasswordHistory,
  queueAdminProfileUpdate,
  getPendingAdminProfileUpdates,
  approveAdminProfileUpdate,
  rejectAdminProfileUpdate,
  getRecentPasswordHashes,
} = require("../../models/admin/adminUserModel");
const {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
} = require("../../utils/jwt");
const {
  generateSecret,
  verifyTOTPToken,
  generateQRCode,
} = require("../../utils/otp");
const {
  comparePassword,
  validatePasswordComplexity,
  hashPassword,
} = require("../../utils/password");
const { error, success } = require("../../utils/response");
const qrCode = require("qrcode");
const refreshTokenModel = require("../../models/admin/refreshTokenModel");
const {
  savePasswordResetToken,
  findValidToken,
  markTokenAsUsed,
} = require("../../models/admin/passwordResetModel");
const { sendPasswordResetEmail } = require("../../utils/email");
const crypto = require("crypto");
const pool = require("../../config/db");

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

    if (!user || !user.is_2fa_enabled || !user.two_fa_secret) {
      return error(res, "2FA not enabled or invalid user", 400);
    }
    const isValid = verifyTOTPToken(user.two_fa_secret, token);

    if (!isValid) {
      return error(res, "Invalid 2FA token", 400);
    }
    const accesstoken = generateAccessToken(user);
    const refereshToken = generateRefreshToken({
      id: user.id,
      roleId: user.role_id,
    });
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 1 day in milliseconds

    await refreshTokenModel.saveRefreshToken({
      adminUserId: user.id,
      token: refereshToken,
      expiresAt,
      userAgent: req.headers["user-agent"],
      ip: req.ip,
    });

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

exports.refereshToken = async (req, res) => {
  if (!req.body) {
    return error(res, "Invalid request. Request body is required", 400);
  }

  try {
    const { refereshToken } = req.body;
    console.log(refereshToken);
    if (!refereshToken) {
      return error(res, "Invalid request. refereshToken is required", 400);
    }

    const payload = verifyRefreshToken(refereshToken);
    const user = await getAdminById(payload.id);

    if (!user) {
      return error(res, "User not found", 400);
    }

    const newAccessToken = generateAccessToken({
      id: user.id,
      username: user.username,
      roleId: user.role_id,
    });
    return success(
      res,
      "Token refreshed successfully",
      { accessToken: newAccessToken },
      200
    );
  } catch (err) {
    console.error(err);
    return error(res, "Something went wrong", 500);
  }
};

exports.logout = async (req, res) => {
  try {
    const refreshToken = req.body.refreshToken;
    if (!refreshToken) {
      return error(res, "Invalid request. refereshToken is required", 400);
    }

    await deleteRefreshToken(refreshToken);

    return success(res, "Logout successful", 200);
  } catch (err) {
    return error(res, err, 500);
  }
};

exports.forgotPassword = async (req, res) => {
  if (!req.body) {
    return error(res, "Invalid request. Request body is required", 400);
  }

  const { email } = req.body;
  if (!email) {
    return error(res, "Invalid request. email is required", 400);
  }

  try {
    const user = await findByUsernameOrEmail(email);
    if (!user) {
      return error(res, "User not found", 400);
    }

    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 1 day in milliseconds

    await savePasswordResetToken(user.id, token, expiresAt);

    await sendPasswordResetEmail(email, token);
    console.log(token);
    return success(res, "Password reset email sent successfully", 200);
  } catch (err) {
    console.error(err);
    return error(res, "Something went wrong", 500);
  }
};

exports.resetPassword = async (req, res) => {
  const {email,  token, newPassword } = req.body;

  if (!email || !token || !newPassword) {
    return error(
      res,
      "Invalid request.Email,  token and newPassword are required",
      400
    );
  }

  try {
    const tokenData = await findValidToken(token);
    if (!tokenData) {
      return error(res, "Invalid token", 400);
    }

    const complexityError = validatePasswordComplexity(newPassword);
    if (complexityError) {
      return error(res, complexityError, 400);
    }

    const hashedPassword = await hashPassword(newPassword);

    await updateAdminPassword(
      tokenData.user_id,
      hashedPassword,
      tokenData.updated_by,
      tokenData.updated_ip,
      tokenData.updated_platform
    );
    await savePasswordHistory(tokenData.user_id, hashedPassword);
    await markTokenAsUsed(tokenData.id);
    return success(res, "Password reset successful", 200);
  } catch (err) {
    console.error(err);
    return error(res, "Something went wrong", 500);
  }
};

exports.getProfile = async (req, res) => {
  try {
    const adminId = req.admin.id;
    const admin = await getAdminById(adminId);

    if (!adminId) {
      return error(res, "Admin User not found", 400);
    }

    return success(res, "Profile fetched successfully", admin, 200);
  } catch (err) {
    return error(res, "Error" + err, 500);
  }
};

exports.requestProfileUpdate = async (req, res) => {
  try {
    const adminId = req.admin.id;
    const { username, email } = req.body;

    if (!username && !email) {
      return error(
        res,
        "Invalid request. username and email are required",
        400
      );
    }
    await queueAdminProfileUpdate(adminId, { username, email });

    return success(res, "Profile update request sent successfully", 200);
  } catch (err) {
    console.error(err);
    return error(res, "Something went wrong", 500);
  }
};

exports.listPendingProfileUpdates = async (req, res) => {
  try {
    const rows = await getPendingAdminProfileUpdates();
    return response.success(res, "Pending updates retrieved", rows);
  } catch (err) {
    console.error("Fetch pending updates failed:", err);
    return response.error(res, "Failed to fetch pending updates");
  }
};

exports.approveProfileUpdate = async (req, res) => {
  try {
    const approverId = req.user.id;
    const { pendingId } = req.body;

    const success = await approveAdminProfileUpdate(pendingId, approverId);
    if (!success) {
      return response.error(res, "Approval failed or already approved", 400);
    }

    return response.success(res, "Profile update approved");
  } catch (err) {
    console.error("Approval error:", err);
    return response.error(res, "Error approving profile update");
  }
};

exports.rejectProfileUpdate = async (req, res) => {
  try {
    const approverId = req.user.id;
    const { pendingId, reason } = req.body;

    await rejectAdminProfileUpdate(pendingId, approverId, reason);
    return response.success(res, "Profile update rejected");
  } catch (err) {
    console.error("Rejection error:", err);
    return response.error(res, "Error rejecting profile update");
  }
};

exports.changePassword = async (req, res) => {
  try {
    const userId = req.user.id;
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
      return response.error(res, "Old and new password are required", 400);
    }

    const user = await getAdminById(userId);
    if (!user) {
      return response.error(res, "User not found", 404);
    }

    const match = await comparePassword(oldPassword, user.password);
    if (!match) {
      return response.error(res, "Old password is incorrect", 401);
    }

    const complexityCheck = validatePasswordComplexity(newPassword);
    if (complexityCheck !== true) {
      return response.error(res, complexityCheck || "Password does not meet complexity requirements", 400);
    }

    const previousHashes = await getRecentPasswordHashes(userId);
    for (let hash of previousHashes) {
      const reused = await comparePassword(newPassword, hash);
      if (reused) {
        return response.error(res, "New password must not match the last 3 passwords", 400);
      }
    }

    const newHashed = await hashPassword(newPassword);
    await updateAdminPassword(userId, newHashed);

    return response.success(res, "Password changed successfully");
  } catch (err) {
    console.error("Change password failed:", err);
    return response.error(res, "Failed to change password");
  }
};