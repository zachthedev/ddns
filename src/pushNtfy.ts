export async function pushNtfy(message: string, env: Env): Promise<void> {
	if (!env.NTFY_URL) {
		return;
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
