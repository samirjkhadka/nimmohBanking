const pool = require("../../config/db");

//Get password hash for an admin user
async function getAdminPasswordHash(adminUserId) {
  const result = await pool.query(
    "SELECT password FROM admin_users WHERE id = $1",
    [adminUserId]
  );
  return result.rows[0]?.password || null;
}

//update the admin user's password
async function updateAdminPassword(
  adminUserId,
  newPasswordHash,
  updatedBy,
  updatedIp,
  updatedPlatform
) {
  return await pool.query(
    `Update admin_users
        SET Password = $1, updated_by = $2, updated_date_utc = CURRENT_TIMESTAMP, updated_ip = $3, updated_platform = $4
        WHERE id = $5;`,
    [newPasswordHash, updatedBy, updatedIp, updatedPlatform, adminUserId]
  );
}

//insert into password history table
async function insertAdminPasswordHistory(adminUserId, passwordHash) {
  return await pool.query(
    "INSERT INTO admin_user_password_history (admin_user_id, password_hash, created_date_UTC) VALUES ($1, $2, CURRENT_TIMESTAMP);",
    [adminUserId, passwordHash]
  );
}

async function findByUsernameOrEmail(identifier) {
  const query = `
    SELECT * FROM admin_users 
    WHERE phone = $1 OR email = $1
    LIMIT 1
  `;
  const result = await pool.query(query, [identifier]);
  return result.rows[0];
}

async function saveOTPSecret(userId, secret) {
  const query = `UPDATE admin_users SET two_fa_secret = $1 WHERE id = $2;`;
  await pool.query(query, [secret, userId]);
}

async function getAdminById (adminUserId) {
  const result = await pool.query(
    "SELECT * FROM admin_users WHERE id = $1",
    [adminUserId]
  );
  return result.rows[0];
}
module.exports = {
  getAdminPasswordHash,
  updateAdminPassword,
  insertAdminPasswordHistory,
  findByUsernameOrEmail,
  saveOTPSecret,
  getAdminById
};
