/**
 * Sends a change notification to an ntfy server. The target comes entirely
 * from the request's `ntfy` parameter (validated upstream); deployments hold
 * no notification configuration, which keeps the worker multi-tenant: every
 * caller gets their own topic, self-hosted servers included.
 */
export async function pushNtfy(messages: string | string[], ntfyUrl: string | null): Promise<void> {
	if (ntfyUrl === null || ntfyUrl === '') {
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
		await fetch(ntfyUrl, {
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
