const pool = require("../../config/db");

exports.saveRefreshToken = async ({
  adminUserId,
  token,
  expiresAt,
  userAgent,
  ip,
}) => {
  await pool.query(
    `INSERT INTO admin_refresh_tokens (admin_user_id, refresh_token, expires_at, user_agent, ip_address)
         VALUES ($1, $2, $3, $4, $5)`,
    [adminUserId, token, expiresAt, userAgent, ip]
  );
};

exports.deleteRefreshToken = async (token) => {

  await pool.query(
    `DELETE FROM admin_refresh_tokens WHERE refresh_token = $1;`,
    [token]
  );
};

exports.findRefreshToken = async (token) => {
  const res = await pool.query(
    `SELECT * FROM admin_refresh_tokens WHERE refresh_token = $1;`,
    [token]
  );
  return res.rows[0];
};
