export function json(data: unknown, init: ResponseInit = {}): Response {
	const headers = new Headers(init.headers);
	headers.set("content-type", "application/json; charset=utf-8");

	return new Response(JSON.stringify(data), {
		...init,
		headers,
	});
}

export function randomToken(bytes = 32): string {
	const value = new Uint8Array(bytes);
	crypto.getRandomValues(value);
	return base64UrlEncode(value);
}

export function base64UrlEncode(input: ArrayBuffer | ArrayBufferView | string): string {
	let bytes: Uint8Array;
	if (typeof input === "string") {
		bytes = new TextEncoder().encode(input);
	} else if (input instanceof ArrayBuffer) {
		bytes = new Uint8Array(input);
	} else {
		bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
	}

	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}

	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

export function base64UrlDecode(input: string): Uint8Array {
	const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
	const padded = normalized + "=".repeat((4 - (normalized.length % 4 || 4)) % 4);
	const binary = atob(padded);
	const bytes = new Uint8Array(binary.length);

	for (let index = 0; index < binary.length; index += 1) {
		bytes[index] = binary.charCodeAt(index);
	}

	return bytes;
}

export function sha256base64Url(value: string): Promise<string> {
	return crypto.subtle
		.digest("SHA-256", new TextEncoder().encode(value))
		.then((digest) => base64UrlEncode(digest));
}

export function ensureTrailingSlash(value: string): string {
	return value.endsWith("/") ? value : `${value}/`;
}

export function secondsFromNow(seconds: number): number {
	return Math.floor(Date.now() / 1000) + seconds;
}

export function currentEpochSeconds(): number {
	return Math.floor(Date.now() / 1000);
}

export function errorDescription(error: unknown): string {
	if (error instanceof Error) {
		return error.message;
	}
	return "Unexpected error";
}
