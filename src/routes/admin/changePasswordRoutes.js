const express = require("express");
const router = express.Router();
const {
  handleChangePassword,
} = require("../../controllers/admin/changePasswordController");
const authenticate = require("../../middlewares/auth");


console.log("changePasswordRoutes");

router.post("/change-password", authenticate, handleChangePassword);

module.exports = router;
