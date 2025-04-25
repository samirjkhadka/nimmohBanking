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
        SET Password = $1, updated_by = $2, updated_at = CURRENT_TIMESTAMP, source_ip = $3, platform = $4
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

async function getAdminById(adminUserId) {
  const result = await pool.query("SELECT * FROM admin_users WHERE id = $1", [
    adminUserId,
  ]);
  return result.rows[0];
}

async function savePasswordHistory(adminUserId, passwordHash) {
  await pool.query(
    "INSERT INTO admin_user_password_history (admin_user_id, password_hash, created_date_UTC) VALUES ($1, $2, CURRENT_TIMESTAMP);",
    [adminUserId, passwordHash]
  );
}

async function queueAdminProfileUpdate(adminId, updates) {
  const { username, email } = updates;

  await pool.query(
    `INSERT INTO admin_user_updates_pending 
      (admin_user_id, new_username, new_email, status, requested_by, requested_date_utc) 
     VALUES ($1, $2, $3, 'PENDING', $1, NOW())`,
    [adminId, username, email]
  );
}

async function getPendingAdminProfileUpdates() {
  const result =
    await pool.query(`SELECT pup.id, pup.admin_user_id, pup.new_username, pup.new_email, pup.status, 
           pup.requested_date_utc, u.username AS current_username, u.email AS current_email
    FROM admin_user_updates_pending pup
    JOIN admin_users u ON pup.admin_user_id = u.id
    WHERE pup.status = 'PENDING'`);
  return result.rows;
}
async function approveAdminProfileUpdate(pendingId, approverId) {
  const result = await pool.query(
    `UPDATE admin_users 
     SET username = pup.new_username, email = pup.new_email 
     FROM admin_user_updates_pending pup 
     WHERE admin_users.id = pup.admin_user_id 
       AND pup.id = $1 
       AND pup.status = 'PENDING'`,
    [pendingId]
  );

  await pool.query(
    `UPDATE admin_user_updates_pending 
     SET status = 'APPROVED', approved_by = $1, approved_date_utc = NOW() 
     WHERE id = $2`,
    [approverId, pendingId]
  );

  return result.rowCount > 0;
}

async function rejectAdminProfileUpdate(pendingId, approverId, reason = null) {
  await pool.query(
    `UPDATE admin_user_updates_pending 
     SET status = 'REJECTED', approved_by = $1, approved_date_utc = NOW(), rejection_reason = $2 
     WHERE id = $3`,
    [approverId, reason, pendingId]
  );
}

async function getRecentPasswordHashes(adminUserId, limit = 3) {
  const result = await pool.query(
    `SELECT password_hash FROM admin_user_password_history 
     WHERE admin_user_id = $1 
     ORDER BY created_date_utc DESC 
     LIMIT $2`,
    [adminUserId, limit]
  );
  return result.rows.map((row) => row.password_hash);
}

async function updateAdminPassword(adminUserId, newPasswordHash) {
  await pool.query(
    `UPDATE admin_users SET password = $1, password_last_changed = NOW(), login_attempts = 0 WHERE id = $2`,
    [newPasswordHash, adminUserId]
  );

  await pool.query(
    `INSERT INTO admin_user_password_history (admin_user_id, password_hash, created_date_utc) 
     VALUES ($1, $2, NOW())`,
    [adminUserId, newPasswordHash]
  );
}

async function createPasswordResetToken(email, token, expiresAt) {
  await pool.query(
    `INSERT INTO password_reset_tokens (email, token, expires_at_utc, created_date_utc) 
     VALUES ($1, $2, $3, NOW())`,
    [email, token, expiresAt]
  );
}

async function getPasswordResetToken(email, token) {
  const result = await pool.query(
    `SELECT * FROM password_reset_tokens 
     WHERE email = $1 AND token = $2 AND used = false AND expires_at_utc > NOW()`,
    [email, token]
  );
  return result.rows[0];
}

async function markTokenUsed(email, token) {
  await pool.query(
    `UPDATE password_reset_tokens SET used = true WHERE email = $1 AND token = $2`,
    [email, token]
  );
}

module.exports = {
  getAdminPasswordHash,
  updateAdminPassword,
  insertAdminPasswordHistory,
  findByUsernameOrEmail,
  saveOTPSecret,
  getAdminById,
  savePasswordHistory,
  queueAdminProfileUpdate,
  getPendingAdminProfileUpdates,
  approveAdminProfileUpdate,
  rejectAdminProfileUpdate,
  getRecentPasswordHashes,
  updateAdminPassword,
  createPasswordResetToken,
  getPasswordResetToken,
  markTokenUsed,
};
