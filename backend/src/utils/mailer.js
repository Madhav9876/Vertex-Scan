// Vertex Scan - Email Mailer
// Sends transactional email (password reset, etc.) via nodemailer.
// Falls back to console logging when SMTP is not configured, so the
// password-reset flow still works end-to-end in development.
const nodemailer = require('nodemailer');

let transporter = null;

function buildTransporter() {
  if (transporter) return transporter;

  const host = process.env.SMTP_HOST;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (host && user && pass) {
    transporter = nodemailer.createTransport({
      host,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === 'true',
      auth: { user, pass },
    });
  } else {
    // No SMTP configured — use a JSON transport that just logs the message.
    transporter = nodemailer.createTransport({ jsonTransport: true });
  }
  return transporter;
}

function isConfigured() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
}

const FROM_ADDRESS = process.env.MAIL_FROM || process.env.SMTP_USER || 'no-reply@vertexscan.app';

async function sendMail({ to, subject, text, html }) {
  const mailOptions = {
    from: FROM_ADDRESS,
    to,
    subject,
    text,
    html: html || text,
  };

  const info = await buildTransporter().sendMail(mailOptions);

  // When SMTP is not configured, nodemailer returns the message as JSON.
  if (!isConfigured()) {
    console.log(
      `\n[MAIL:DEV-FALLBACK] To: ${to}\nSubject: ${subject}\n` +
      `----------------------------------------\n${text}\n----------------------------------------\n`
    );
  }
  return info;
}

function buildResetEmail({ email, resetUrl, expiresMinutes }) {
  const subject = 'Vertex Scan — Reset your password';
  const text =
    `Hello,\n\n` +
    `We received a request to reset the password for your Vertex Scan account (${email}).\n` +
    `Click the link below to choose a new password. This link expires in ${expiresMinutes} minutes.\n\n` +
    `${resetUrl}\n\n` +
    `If you did not request this, you can safely ignore this email — your password will not change.\n\n` +
    `— The Vertex Scan Team`;

  const html =
    `<div style="font-family:Arial,Helvetica,sans-serif;max-width:480px;margin:0 auto;color:#111;">` +
    `<h2 style="color:#0ea5e9;">Vertex Scan</h2>` +
    `<p>Hello,</p>` +
    `<p>We received a request to reset the password for your Vertex Scan account ` +
    `(<strong>${email}</strong>).</p>` +
    `<p><a href="${resetUrl}" style="display:inline-block;background:#0ea5e9;color:#fff;` +
    `padding:10px 18px;border-radius:6px;text-decoration:none;font-weight:600;">Reset my password</a></p>` +
    `<p>This link expires in <strong>${expiresMinutes} minutes</strong>.</p>` +
    `<p>If you did not request this, you can safely ignore this email — your password will not change.</p>` +
    `<hr style="border:none;border-top:1px solid #eee;margin:24px 0;" />` +
    `<p style="font-size:12px;color:#888;">— The Vertex Scan Team</p>` +
    `</div>`;

  return { subject, text, html };
}

module.exports = { sendMail, buildResetEmail, isConfigured };
