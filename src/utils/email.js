const nodemailer = require("nodemailer");
const { EMAIL } = require("../config/config");

const transporter = nodemailer.createTransport({
  service: EMAIL.service,
  host:EMAIL.host,
  auth: {
    user: EMAIL.nodemailerUser,
    pass: EMAIL.nodemailerPass,
  },
});

const sendPasswordResetEmail = async (toEmail, token) => {
  const resetUrl = `https://finexa.neemohlabs.com.np/admin/reset-password?token=${token}`; // Replace with your frontend URL
  const html = `<p> Click the link below to reset your password: <a href="${resetUrl}">Reset Password</a></p>`;

  const mailOptions = {
    from: EMAIL.nodemailerUser,
    to: toEmail,
    subject: "Temporary Password - Admin -Nimmoh Agency Banking",
    html: `<p> Click the link below to reset your password: <a href="${resetUrl}">Reset Password</a></p>`,
  };
  try {
    const info = await transporter.sendMail(mailOptions);
    console.log(`Email sent to user: ${toEmail}`, info.response);
  } catch (error) {
    console.error("Error sending email:", error);
  }
};

module.exports = { sendPasswordResetEmail };