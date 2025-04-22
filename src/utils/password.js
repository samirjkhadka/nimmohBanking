const bcrypt = require("bcrypt");
const pool = require("../config/db");
const PASSWORD_POLICY = {
  MIN_LENGTH: 12,
  MAX_LENGTH: 32,
  MIN_UPPERCASE: 1,
  MIN_LOWERCASE: 1,
  MIN_NUMBER: 1,
  MIN_SYMBOL: 1,
  MAX_CONSECUTIVE: 3,
  MAX_CONSECUTIVE_CHARS: 3,
  MAX_CONSECUTIVE_NUMBERS: 3,
  MAX_CONSECUTIVE_SYMBOLS: 3,
  MAX_CONSECUTIVE_LOWERCASE: 3,
  MAX_CONSECUTIVE_UPPERCASE: 3,
  PATTERN: /^(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,32}$/,
};

function hasConsecutiveChars(str, maxConsecutive) {
  let count = 1;
  for (let i = 1; i < str.length; i++) {
    if (str[i] === str[i - 1]) {
      count++;
      if (count > maxConsecutive) {
        return true;
      }
    } else {
      count = 1;
    }
  }
  return false;
}

function validatePasswordComplexity(password) {
  const {
    MIN_LENGTH,
    MAX_LENGTH,
    MIN_UPPERCASE,
    MIN_LOWERCASE,
    MIN_NUMBER,
    MIN_SYMBOL,
    MAX_CONSECUTIVE,
    MAX_CONSECUTIVE_CHARS,
    MAX_CONSECUTIVE_NUMBERS,
    MAX_CONSECUTIVE_SYMBOLS,
    MAX_CONSECUTIVE_LOWERCASE,
    MAX_CONSECUTIVE_UPPERCASE,
    PATTERN,
  } = PASSWORD_POLICY;
  if (password.length < MIN_LENGTH || password.length > MAX_LENGTH) {
    return `Password must be between ${MIN_LENGTH} and ${MAX_LENGTH} characters.`;
  }

  if (!PATTERN.test(password)) {
    return "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.";
  }

  const upperCase = password.match(/[A-Z]/g || []);
  const lowerCase = password.match(/[a-z]/g || []);
  const number = password.match(/[0-9]/g || []);
  const symbol = password.match(/[@$!%*?&]/g || []);

  if (
    upperCase.length < MIN_UPPERCASE ||
    lowerCase.length < MIN_LOWERCASE ||
    number.length < MIN_NUMBER ||
    symbol.length < MIN_SYMBOL
  ) {
    return "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.";
  }
  if (
    hasConsecutiveChars(password, /[A-Z]/, MAX_CONSECUTIVE_CHARS) ||
    hasConsecutiveChars(password, /[a-z]/, MAX_CONSECUTIVE_LOWERCASE) ||
    hasConsecutiveChars(password, /[0-9]/, MAX_CONSECUTIVE_NUMBERS) ||
    hasConsecutiveChars(password, /[@$!%*?&]/, MAX_CONSECUTIVE_SYMBOLS)
  ) {
    return `Password must not contain more than ${MAX_CONSECUTIVE} consecutive characters.`;
  }
  return null;
}

async function hashPassword(password) {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
}

async function comparePassword(password, hashed) {
  return await bcrypt.compare(password, hashed);
}

async function isPasswordReused(userId, newPassword) {
  const result = await pool.query(
    "SELECT password FROM admin_user_password_history WHERE admin_user_id = $1 ORDER BY created_date_utc DESC LIMIT 3",
    [userId]
  );
  const recentHashes = result.rows.map((row) => row.password_hash);
  for (let hash of recentHashes) {
    const match = await bcrypt.compare(newPassword, hash);
    if (match) {
      return true;
    }
    return false;
  }
}

module.exports = {
  validatePasswordComplexity,
  hashPassword,
  comparePassword,
  isPasswordReused,
  PASSWORD_POLICY,
};

// const password = "Abc123!@#";
