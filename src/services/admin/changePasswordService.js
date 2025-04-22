const {
  validatePasswordComplexity,
  hashPassword,
  comparePassword,
  isPasswordReused,
} = require("../../utils/password");

const {
  getAdminPasswordHash,
  updateAdminPassword,
  insertAdminPasswordHistory,
} = require("../../models/admin/adminUserModel");

async function changeAdminPassword({
  adminUserId,
  currentPassword,
  newPassword,
  updatedBy,
  updatedIP,
  updatedPlatform,
}) {
  const existingHash = await getAdminPasswordHash(adminUserId);
  if (!existingHash) {
    throw new Error("Admin user not found");
  }
  const match = await comparePassword(currentPassword, existingHash);
  if (!match) {
    throw new Error("Current password is incorrect");
  }
  const reused = await isPasswordReused(adminUserId, newPassword);
  if (reused) {
    throw new Error("New password cannot be reused");
  }
  const complexityError = validatePasswordComplexity(newPassword);
  if (complexityError) {
    throw new Error(complexityError);
  }
  const newPasswordHash = await hashPassword(newPassword);
  await updateAdminPassword(
    adminUserId,
    newPasswordHash,
    updatedBy,
    updatedIP,
    updatedPlatform
  );
  await insertAdminPasswordHistory(adminUserId, newPasswordHash);
  return true;
}

module.exports =  changeAdminPassword ;
