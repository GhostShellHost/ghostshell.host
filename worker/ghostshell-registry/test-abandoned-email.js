// Quick script to trigger an abandoned checkout email via the worker's webhook
// This uses the real Resend setup already configured

const TEST_EMAIL = 'jasonvbutler@me.com';
const WORKER_URL = 'https://ghostshell.host/api/stripe/webhook';

async function sendTest() {
  // Create a mock Stripe checkout.session.expired event
  const mockEvent = {
    id: 'evt_test_' + Date.now(),
    type: 'checkout.session.expired',
    data: {
      object: {
        id: 'cs_test_' + Date.now(),
        customer_details: { email: TEST_EMAIL },
        metadata: { recovery_email: TEST_EMAIL }
      }
    }
  };

  // We need the Stripe webhook secret to sign, but the worker also has an idempotency guard
  // that will reject duplicate event IDs. Since this is a new test ID, it should process.
  // However, without a valid signature, the worker will reject.
  // Better: call a new test endpoint I'll add quickly.

  console.log('Mock event:', JSON.stringify(mockEvent, null, 2));
  console.log('Would send to:', WORKER_URL);
}

sendTest().catch(console.error);
