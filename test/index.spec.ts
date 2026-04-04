import { env } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import app from '../src/index';
import type { AdapterEnv } from '../src/types';

const rsaPrivateJwk = {
	kty: 'RSA',
	n: 'ot0dJARsgyafRkLMI52BQLS1FR1yrAoa3horIxWtxDpFBHXAK_71SV7cMytNbwuz0fP6FL5crPrZJodixJgUaBbveCJ3ZCHTrH7YqN-3_fWS4q5BK2wlUdUWyyfcZI3j4_gAEPXLd-gxh5LRCeikihjAOjGd5gybEvhGw0mTU4u4YQ_nYwzCBD7WcDTNALqgY5-j0ZSTWE0CZ1Hi2v3Gxmco-ta40Cszo0hv8Zoe_FHSeTMqypB8NYNoNmCRY1gVfoTG5G22P77_XdkSMDKbRNi9CwpQ6bx8ifSHAh3R_pY42pTOEdAZb0HpmgGp0NKlpss13ZT9QV4TZRcTW0Xi4Q',
	e: 'AQAB',
	d: 'BXfNBFTjBnLj2BUNYN4R5TKWqH3TnXO9ZoWUZdooJQrGdG7g-S6B3RPClYk3pqnK62_4jn0RrtEWkf-WUP7AzfnZ0mZogcPM-ov2XufGoqUoaFSXZYt8-Ua2kYg7aGOHKjPntKoRScD8S2P3gWX-guXFK8RXW85CipwsAV8qrhxYuyUNr_tQ2jGgB37-iUzpoTCV4N9WFmCGFMtmSRGSuPxqPn3BxrC2fYPCAyrs1vaXfif7KRoFdjitpFNE7-e01xQ5mgTR61cwyI-8bUIjIvN34pVNPF5eOeqHvemYNkZW14r0YxTCisgi6q_Eh9gtv3O3JCaxgm95iNDUWRBYQQ',
	p: '1nXaYW5GFSHfsQ1XYPORYVYx19DFVoXpIB7OHw4jlJJiid_zSoqWvAY_fZ05sN5BYPNslkl0xDR7tyUZyGnCp-Xx2bOBq3qXDTo34yVfTgiLUhUfwv3zHzw8cQXYr4nHKejJy9zowHAD6Q_dO7rEm_o6WjgWvHkXdimzv2YE67k',
	q: 'wmjPbgYIn8Fj4-h3WBVKuSpB9x1AIvzS-tWCSCXB05ZuRpOd3Q8IytAo13ZbYzuQ4Aq0PPa2gn7Sk4PjPWrAlVVvSMQM-aYKQ2CmnVbFwnaZVVBzUh5nhpy1I7OXnAOoB7S8KcyGNCsuSqww2pDVbLo9o-6nwCCfgYvvRe5s1Gk',
	dp: 'gkTqVx6F4ZZG66Rf_FtXZtnVwvNku27yMfmkWQbcpAXbZ0aq4Q-YCjR9Yo8bmQ0Yh4y13ABYtknvEEuwAqYDgLtTklrQnFoF4RoJEqgD4UGdZ0m_llFt2f5b9IeJnO9DFHj8AyJ4G1Sve2WQjBSiEuEHiv_hB7FCiBtCvTN6L7k',
	dq: 'Sp0xZ5fXPYFa1kEFdQAPAswuLyrBz-vbCbxiWVBseMnWny3Ou-YmSLjlw_RAFPDqpKJXFMLXv3PvXACVeZ_8NBRrNrFQDYzliYCR0fdYxU8BgJX0_MKAl1CT0RT_jjh1CCgcw6oko-ciyDQYN_q4fxdnywAwz_N1ZKIRfnSIvmk',
	qi: 'CUaB5nua15RbtUVozBtAl7SbKEwBKfEX3_IzrrjqWGxGSkzz21T3RoWPbHwo3Ls9cMj-bPwqBk2gDPq9ly_X_5NnYY2e9S8YOYzrjynNfRySr41mhJj4t6QVeYBfcC0Gv7-oEL4BPvt53JlInt2xBRMK_AYYSv7-CCJpr7SjCTg',
	alg: 'RS256',
};

const originalFetch = globalThis.fetch;
const mockEnv = createMockEnv();

beforeEach(async () => {
	expect(mockEnv.ESA_TEAM).toBe('docs');
	expect(mockEnv.ESA_CLIENT_ID).toBe('test-client-id');
	expect(JSON.parse(mockEnv.OIDC_JWT_PRIVATE_KEY)).toMatchObject({
		kty: rsaPrivateJwk.kty,
		e: rsaPrivateJwk.e,
	});
	globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;

		if (url === 'https://api.esa.io/oauth/token') {
			return Response.json({
				access_token: 'esa-access-token',
				token_type: 'Bearer',
				scope: 'read',
				created_at: 1711868400,
			});
		}

		if (url === 'https://api.esa.io/v1/user') {
			return Response.json({
				id: 42,
				name: 'Ada Lovelace',
				screen_name: 'ada',
				icon: 'https://img.esa.io/avatar.png',
				email: 'ada@example.com',
			});
		}

		return originalFetch(input, init);
	};
});

afterEach(() => {
	globalThis.fetch = originalFetch;
});

describe('esa OIDC adapter', () => {
	it('returns discovery metadata', async () => {
		const response = await request('https://adapter.example.com/.well-known/openid-configuration');

		expect(response.status).toBe(200);
		await expect(response.json()).resolves.toMatchObject({
			issuer: 'https://adapter.example.com',
			authorization_endpoint: 'https://adapter.example.com/authorize',
			token_endpoint_auth_methods_supported: ['client_secret_post'],
		});
	});

	it('rejects authorize requests missing openid scope', async () => {
		const response = await request(
			'https://adapter.example.com/authorize?client_id=test-client-id&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&response_type=code&scope=profile',
			{ redirect: 'manual' },
		);

		expect(response.status).toBe(400);
		await expect(response.json()).resolves.toMatchObject({
			error: 'invalid_scope',
		});
	});

	it('redirects authorize requests to esa', async () => {
		const response = await request(
			'https://adapter.example.com/authorize?client_id=test-client-id&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&response_type=code&scope=openid%20profile%20email&state=client-state&nonce=nonce-123',
			{ redirect: 'manual' },
		);

		expect(response.status).toBe(302);
		const location = response.headers.get('location');
		expect(location).toContain('https://api.esa.io/oauth/authorize');
		expect(location).toContain('scope=read');
	});

	it('completes authorize callback to token to userinfo', async () => {
		const authorize = await request(
			'https://adapter.example.com/authorize?client_id=test-client-id&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&response_type=code&scope=openid%20profile%20email&state=client-state&nonce=nonce-123',
			{ redirect: 'manual' },
		);
		const esaLocation = new URL(authorize.headers.get('location')!);
		const callbackState = esaLocation.searchParams.get('state')!;

		const callback = await request(`https://adapter.example.com/callback?code=esa-code-123&state=${encodeURIComponent(callbackState)}`, {
			redirect: 'manual',
		});
		const clientRedirect = new URL(callback.headers.get('location')!);
		const adapterCode = clientRedirect.searchParams.get('code')!;

		const tokenResponse = await request('https://adapter.example.com/token', {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
			},
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				code: adapterCode,
				client_id: 'test-client-id',
				client_secret: 'test-client-secret',
				redirect_uri: 'https://client.example.com/cb',
			}),
		});

		expect(tokenResponse.status).toBe(200);
		const tokenBody = await tokenResponse.json<{
			access_token: string;
			id_token: string;
			scope: string;
		}>();
		expect(tokenBody.scope).toBe('openid profile email');
		const idPayload = decodeJwtPayload(tokenBody.id_token);
		expect(idPayload).toMatchObject({
			iss: 'https://adapter.example.com',
			aud: 'test-client-id',
			sub: '42',
			nonce: 'nonce-123',
			token_use: 'id',
		});

		const userInfo = await request('https://adapter.example.com/userinfo', {
			headers: {
				authorization: `Bearer ${tokenBody.access_token}`,
			},
		});
		expect(userInfo.status).toBe(200);
		await expect(userInfo.json()).resolves.toMatchObject({
			sub: '42',
			name: 'Ada Lovelace',
			preferred_username: 'ada',
			email: 'ada@example.com',
		});
	});

	it('rejects invalid and reused authorization codes', async () => {
		const invalidResponse = await request('https://adapter.example.com/token', {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
			},
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				code: 'missing-code',
				client_id: 'test-client-id',
				client_secret: 'test-client-secret',
				redirect_uri: 'https://client.example.com/cb',
			}),
		});
		expect(invalidResponse.status).toBe(400);

		const authorize = await request(
			'https://adapter.example.com/authorize?client_id=test-client-id&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&response_type=code&scope=openid%20profile&state=client-state',
			{ redirect: 'manual' },
		);
		const callbackState = new URL(authorize.headers.get('location')!).searchParams.get('state')!;
		const callback = await request(`https://adapter.example.com/callback?code=esa-code-abc&state=${encodeURIComponent(callbackState)}`, {
			redirect: 'manual',
		});
		const adapterCode = new URL(callback.headers.get('location')!).searchParams.get('code')!;

		const first = await request('https://adapter.example.com/token', {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
			},
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				code: adapterCode,
				client_id: 'test-client-id',
				client_secret: 'test-client-secret',
				redirect_uri: 'https://client.example.com/cb',
			}),
		});
		expect(first.status).toBe(200);

		const second = await request('https://adapter.example.com/token', {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
			},
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				code: adapterCode,
				client_id: 'test-client-id',
				client_secret: 'test-client-secret',
				redirect_uri: 'https://client.example.com/cb',
			}),
		});
		expect(second.status).toBe(400);
		await expect(second.json()).resolves.toMatchObject({
			error: 'invalid_grant',
		});
	});

	it('allows login even when esa email is absent', async () => {
		globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;

			if (url === 'https://api.esa.io/oauth/token') {
				return Response.json({
					access_token: 'esa-access-token-no-email',
					token_type: 'Bearer',
					scope: 'read',
					created_at: 1711868400,
				});
			}

			if (url === 'https://api.esa.io/v1/user') {
				return Response.json({
					id: 77,
					name: 'Grace Hopper',
					screen_name: 'grace',
					icon: 'https://img.esa.io/grace.png',
				});
			}

			return originalFetch(input, init);
		};

		const authorize = await request(
			'https://adapter.example.com/authorize?client_id=test-client-id&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&response_type=code&scope=openid%20profile&state=client-state',
			{ redirect: 'manual' },
		);
		const callbackState = new URL(authorize.headers.get('location')!).searchParams.get('state')!;
		const callback = await request(
			`https://adapter.example.com/callback?code=esa-code-no-email&state=${encodeURIComponent(callbackState)}`,
			{ redirect: 'manual' },
		);
		const adapterCode = new URL(callback.headers.get('location')!).searchParams.get('code')!;

		const tokenResponse = await request('https://adapter.example.com/token', {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
			},
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				code: adapterCode,
				client_id: 'test-client-id',
				client_secret: 'test-client-secret',
				redirect_uri: 'https://client.example.com/cb',
			}),
		});

		expect(tokenResponse.status).toBe(200);
		const tokenBody = await tokenResponse.json<{ access_token: string; id_token: string }>();
		const idPayload = decodeJwtPayload(tokenBody.id_token);
		expect(idPayload.email).toBeUndefined();

		const userInfo = await request('https://adapter.example.com/userinfo', {
			headers: {
				authorization: `Bearer ${tokenBody.access_token}`,
			},
		});
		await expect(userInfo.json()).resolves.toMatchObject({
			sub: '77',
			name: 'Grace Hopper',
		});
	});

	it('maps upstream failures to server errors', async () => {
		globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;

			if (url === 'https://api.esa.io/oauth/token') {
				return new Response('bad upstream', { status: 500 });
			}

			return originalFetch(input, init);
		};

		const authorize = await request(
			'https://adapter.example.com/authorize?client_id=test-client-id&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&response_type=code&scope=openid%20profile&state=client-state',
			{ redirect: 'manual' },
		);
		const callbackState = new URL(authorize.headers.get('location')!).searchParams.get('state')!;
		const callback = await request(`https://adapter.example.com/callback?code=esa-code-fails&state=${encodeURIComponent(callbackState)}`, {
			redirect: 'manual',
		});
		const adapterCode = new URL(callback.headers.get('location')!).searchParams.get('code')!;

		const tokenResponse = await request('https://adapter.example.com/token', {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
			},
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				code: adapterCode,
				client_id: 'test-client-id',
				client_secret: 'test-client-secret',
				redirect_uri: 'https://client.example.com/cb',
			}),
		});

		expect(tokenResponse.status).toBe(500);
		await expect(tokenResponse.json()).resolves.toMatchObject({
			error: 'server_error',
		});
	});
});

function decodeJwtPayload(token: string): Record<string, unknown> {
	const [, payload] = token.split('.');
	if (!payload) {
		throw new Error('Malformed JWT');
	}

	const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
	const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
	return JSON.parse(atob(padded));
}

async function request(input: string | Request, init?: RequestInit): Promise<Response> {
	return await app.request(input, init, mockEnv);
}

function createMockEnv(): AdapterEnv {
	return {
		...env,
		ESA_TEAM: 'docs',
		ESA_CLIENT_ID: 'test-client-id',
		ESA_CLIENT_SECRET: 'test-client-secret',
		ISSUER_URL: 'https://adapter.example.com',
		OIDC_JWT_PRIVATE_KEY: JSON.stringify(rsaPrivateJwk),
		TRANSIENT_STORE: env.TRANSIENT_STORE,
	};
}
