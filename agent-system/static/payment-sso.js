'use strict';
(async () => {
  const status = document.getElementById('sso-status');
  try {
    const params = new URLSearchParams(location.search);
    const state = params.get('state'), challenge = params.get('challenge');
    if (![state, challenge].every(value => /^[A-Za-z0-9_-]{43}$/.test(value || ''))) {
      throw new Error('This sign-in link is invalid. Return to the payment site and start again.');
    }
    // Same-origin fetch sends the academy's Strict cookie after a cross-site navigation.
    const sessionResponse = await fetch('/api/session', {cache: 'no-store'});
    const session = await sessionResponse.json();
    if (!sessionResponse.ok) throw new Error(session.error || 'Sign-in is temporarily unavailable.');
    if (!session.user) {
      location.replace('/admin?' + new URLSearchParams({payment_state: state, payment_challenge: challenge}));
      return;
    }
    const response = await fetch('/api/payment-sso/authorize', {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': session.user.csrf},
      body: JSON.stringify({state, challenge})
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Could not continue to checkout.');
    location.replace(result.redirect_url);
  } catch (error) {
    status.textContent = error.message;
  }
})();
