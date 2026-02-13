// Quick test script to send via Resend using the same logic as worker
// We'll fetch the env vars from Cloudflare via wrangler's dev environment

import { sendEmail } from './worker.js';

// Mock env with actual secrets from Cloudflare
async function getEnv() {
  // In dev, wrangler injects env vars; we can also read from .dev.vars
  const env = {
    RESEND_API_KEY: process.env.RESEND_API_KEY,
    RESEND_FROM_EMAIL: process.env.RESEND_FROM_EMAIL,
  };
  console.log('FROM:', env.RESEND_FROM_EMAIL);
  console.log('API KEY present:', !!env.RESEND_API_KEY);
  return env;
}

async function main() {
  const env = await getEnv();
  if (!env.RESEND_API_KEY || !env.RESEND_FROM_EMAIL) {
    console.error('Missing Resend config in env');
    process.exit(1);
  }

  const result = await sendEmail(env, {
    to: 'jasonvbutler@me.com',
    subject: 'Test email from GhostShell Resend',
    text: 'This is a test email sent via the GhostShell worker Resend setup.\n\nIf you receive this, hello@ghostshell.host can be used as a contact address on the homepage.',
    html: '<p>This is a test email sent via the GhostShell worker Resend setup.</p><p>If you receive this, hello@ghostshell.host can be used as a contact address on the homepage.</p>',
  });

  console.log('Result:', JSON.stringify(result, null, 2));
}

main().catch(console.error);
