const express = require("express");
const router = express.Router();
const adminAuthController = require("../../controllers/admin/adminAuthController");

router.post("/login", adminAuthController.login);
router.post("/verify-2fa", adminAuthController.verify2FA);
router.post("/2fa/Setup", adminAuthController.setup2FA);
router.post("/refresh-token", adminAuthController.refereshToken);

module.exports = router;
