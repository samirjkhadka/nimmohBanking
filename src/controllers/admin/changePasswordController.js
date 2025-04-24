
const { error, success } = require("../../utils/response");

async function handleChangePassword(req, res) {
  try {
    const adminUserId = req.user.id;
    const { currentPassword, newPassword } = req.body;
    const ip = req.ip;
    const platform = req.headers["user-agent"] || "";

    await changeAdminPassword({
      adminUserId,
      currentPassword,
      newPassword,
      updatedBy: adminUserId,
      updatedIP: ip,
      updatedPlatform: platform,
    });

    return success(res, "Password changed successfully", [], 200);
  } catch (err) {
    return error(res, err.message);
  }
}
