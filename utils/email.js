// utils/email.js
const nodemailer = require('nodemailer');

const transport = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

module.exports.sendPasswordResetEmail = async (toEmail, resetURL) => {
  const message = `
    <p>You requested a password reset. Click the link below to reset your password:</p>
    <p><a href="${resetURL}">${resetURL}</a></p>
    <p>This link will expire in 10 minutes.</p>
    <p>If you didn’t request this, please ignore.</p>
  `;

  await transport.sendMail({
    from: `"eStore Support" <${process.env.EMAIL_USER}>`,
    to: toEmail,
    subject: "🔑 eStore Password Reset",
    html: message,
  });
};
