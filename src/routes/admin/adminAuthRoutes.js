const express = require("express");
const router = express.Router();
const adminAuthController = require("../../controllers/admin/adminAuthController");
const { verifyAdminToken } = require("../../middlewares/auth");
const { success } = require("../../utils/response");

router.post("/login", adminAuthController.login);
router.post("/verify-2fa", adminAuthController.verify2FA);
router.post("/2fa/Setup", adminAuthController.setup2FA);
router.post("/refresh-token", adminAuthController.refereshToken);
router.post("/logout", adminAuthController.logout);
router.post("/forgot-password", adminAuthController.forgotPassword);
router.post("/reset-password", adminAuthController.resetPassword);
router.get("/dashboard", verifyAdminToken, (req, res) => {
  return success(res, "Dashboard", { user: req.user }, 200);
});

module.exports = router;
