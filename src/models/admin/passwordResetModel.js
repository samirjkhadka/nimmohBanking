const pool = require("../../config/db");

exports.savePasswordResetToken = async (adminUserId, token, expiresAt) => {
  const query = `Insert into password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3) RETURNING *;`;

  const values = [adminUserId, token, expiresAt];
  const result = await pool.query(query, values);
  return result.rows[0];
};

exports.findValidToken = async (token) => {
  const query = `SELECT * FROM password_reset_tokens WHERE token = $1 AND is_used = FALSE AND expires_at > NOW();`;
  const result = await pool.query(query, [token]);
  return result.rows[0];
};

exports.markTokenAsUsed = async (tokenId) => {
  const query = `UPDATE password_reset_tokens SET is_used = TRUE WHERE token = $1;`;
  await pool.query(query, [tokenId]);
};
