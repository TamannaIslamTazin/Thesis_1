/**
 * Email Service — sends transactional emails via SMTP (Nodemailer).
 *
 * When SMTP_HOST is configured, emails are sent via SMTP.
 * Errors propagate to callers — no silent swallowing.
 */

import nodemailer from 'nodemailer';
import type { Transporter } from 'nodemailer';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';

// ---------------------------------------------------------------------------
// Transporter singleton
// ---------------------------------------------------------------------------

let transporter: Transporter | null = null;
let smtpVerified = false;

function getTransporter(): Transporter | null {
  if (transporter) return transporter;

  if (!config.smtpHost) {
    return null;
  }

  transporter = nodemailer.createTransport({
    host: config.smtpHost,
    port: config.smtpPort,
    secure: config.smtpSecure as unknown as boolean,
    auth: config.smtpUser
      ? { user: config.smtpUser, pass: config.smtpPass }
      : undefined,
  });

  logger.info('SMTP transporter created', {
    host: config.smtpHost,
    port: config.smtpPort,
    user: config.smtpUser ? `${config.smtpUser.slice(0, 4)}...` : '(none)',
    from: config.smtpFrom,
  });

  return transporter;
}

/**
 * Verify SMTP connection on first use. Logs the result but does not block.
 * Called once after transporter creation.
 */
async function verifySmtp(transport: Transporter): Promise<void> {
  if (smtpVerified) return;
  smtpVerified = true;

  try {
    await transport.verify();
    logger.info('SMTP connection verified successfully');
  } catch (error) {
    logger.error('SMTP connection verification failed', {
      error: error instanceof Error ? error.message : String(error),
      host: config.smtpHost,
      port: config.smtpPort,
      user: config.smtpUser,
    });
    // Don't throw — let the actual send attempt surface the real error
  }
}

// ---------------------------------------------------------------------------
// Core send function
// ---------------------------------------------------------------------------

interface SendMailOptions {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

/**
 * Send an email. Throws if SMTP is not configured or delivery fails.
 */
export async function sendMail(opts: SendMailOptions): Promise<void> {
  const transport = getTransporter();

  if (!transport) {
    throw new Error(
      'SMTP is not configured. Set SMTP_HOST, SMTP_USER, and SMTP_PASS in your environment to enable email delivery.'
    );
  }

  // Verify SMTP on first use
  await verifySmtp(transport);

  logger.info('Sending email', { to: opts.to, subject: opts.subject, from: config.smtpFrom });

  const info = await transport.sendMail({
    from: config.smtpFrom,
    to: opts.to,
    subject: opts.subject,
    text: opts.text,
    html: opts.html,
  });

  logger.info('Email sent', {
    messageId: info.messageId,
    to: opts.to,
    response: info.response,
  });
}

// ---------------------------------------------------------------------------
// Template helpers
// ---------------------------------------------------------------------------

export async function sendLoginCode(email: string, code: string): Promise<void> {
  return sendMail({
    to: email,
    subject: 'Your SSI Healthcare Login Code',
    text: `Your login code is: ${code}\n\nThis code expires in 10 minutes. If you didn't request this, please ignore this email.`,
    html: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 480px; margin: 0 auto; padding: 32px;">
        <h2 style="color: #1a1a2e; margin-bottom: 8px;">SSI Healthcare</h2>
        <p style="color: #555; font-size: 16px;">Your login verification code is:</p>
        <div style="background: #f0f4ff; border-radius: 12px; padding: 24px; text-align: center; margin: 24px 0;">
          <span style="font-size: 36px; font-weight: 700; letter-spacing: 8px; color: #1a1a2e; font-family: monospace;">${code}</span>
        </div>
        <p style="color: #888; font-size: 14px;">This code expires in 10 minutes.<br/>If you didn't request this, please ignore this email.</p>
      </div>
    `,
  });
}

export async function sendWelcomeEmail(email: string, firstName?: string): Promise<void> {
  const name = firstName || 'there';
  return sendMail({
    to: email,
    subject: 'Welcome to SSI Healthcare',
    text: `Hi ${name},\n\nWelcome to SSI Healthcare! Your account has been created. You can now manage your health credentials with full privacy and control.\n\nGet started by setting up your wallet.`,
    html: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 480px; margin: 0 auto; padding: 32px;">
        <h2 style="color: #1a1a2e; margin-bottom: 8px;">Welcome to SSI Healthcare</h2>
        <p style="color: #555; font-size: 16px;">Hi ${name},</p>
        <p style="color: #555; font-size: 16px;">Your account has been created. You can now manage your health credentials with full privacy and control.</p>
        <p style="color: #555; font-size: 16px;">Get started by setting up your wallet.</p>
      </div>
    `,
  });
}

/**
 * Run SMTP startup check — call this at server init to catch misconfiguration early.
 * Logs result but never throws so the server still starts.
 */
export async function testSmtpConnection(): Promise<void> {
  const transport = getTransporter();
  if (!transport) {
    logger.warn('SMTP not configured — set SMTP_HOST, SMTP_USER, SMTP_PASS in .env to enable email delivery');
    return;
  }
  await verifySmtp(transport);
}

export async function sendEmergencyAccessNotification(
  email: string,
  requesterName: string,
  requesterRole: string,
  reason: string,
): Promise<void> {
  return sendMail({
    to: email,
    subject: '🚨 Emergency Access to Your Health Records',
    text: `Emergency access has been granted to your health records.\n\nRequester: ${requesterName} (${requesterRole})\nReason: ${reason}\n\nIf this was not authorised, please contact support immediately.`,
    html: `
      <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 480px; margin: 0 auto; padding: 32px;">
        <h2 style="color: #c0392b; margin-bottom: 8px;">🚨 Emergency Access Alert</h2>
        <p style="color: #555; font-size: 16px;">Emergency access has been granted to your health records.</p>
        <div style="background: #fff5f5; border-left: 4px solid #c0392b; padding: 16px; margin: 16px 0; border-radius: 4px;">
          <p style="margin: 4px 0;"><strong>Requester:</strong> ${requesterName}</p>
          <p style="margin: 4px 0;"><strong>Role:</strong> ${requesterRole}</p>
          <p style="margin: 4px 0;"><strong>Reason:</strong> ${reason}</p>
        </div>
        <p style="color: #888; font-size: 14px;">If this was not authorised, please contact support immediately.</p>
      </div>
    `,
  });
}
