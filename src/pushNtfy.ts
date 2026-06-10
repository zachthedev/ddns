export async function pushNtfy(messages: string | string[], env: Env): Promise<void> {
	// The ntfy integration is optional; without the secret, updates proceed
	// silently instead of failing after the DNS write.
	if (!env.NTFY_URL) {
		console.log('NTFY_URL not configured; skipping notification.');
		return;
	}

	let message: string;
	if (Array.isArray(messages)) {
		if (messages.length === 0) {
			return; // No messages to send
		}
		if (messages.length === 1) {
			const firstMessage = messages[0];
			if (firstMessage === null || firstMessage === undefined || firstMessage === '') {
				return; // No valid message
			}
			message = firstMessage;
		} else {
			message = `DNS Records Updated:\n${messages.map((msg) => `• ${msg}`).join('\n')}`;
		}
	} else {
		message = messages;
	}

	try {
		await fetch(env.NTFY_URL, {
			method: 'POST',
			body: message,
			headers: { 'Content-Type': 'text/plain' },
			// Best-effort notification; never let a hung ntfy server hold the request
			signal: AbortSignal.timeout(5000),
		});
	} catch (e) {
		console.error('Failed to send ntfy push: ', e);
	}
}
