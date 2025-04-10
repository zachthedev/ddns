export async function pushNtfy(message: string, env: Env): Promise<void> {
	if (!env.NTFY_URL) {
		throw new Error('NTFY_URL missing from env or empty');
	}
	try {
		await fetch(env.NTFY_URL, {
			method: 'POST',
			body: message,
			headers: { 'Content-Type': 'text/plain' },
		});
	} catch (e) {
		console.error('Failed to send ntfy push: ', e);
	}
}
