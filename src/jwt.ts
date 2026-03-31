import jwt from "@tsndr/cloudflare-worker-jwt";
import type { JwtPayload } from "./types";
import { sha256base64Url } from "./utils";

interface CachedKeys {
	privateJwk: PrivateJwk;
	publicJwk: PublicJwk;
	kid: string;
}

type PrivateJwk = JsonWebKey & {
	kty: string;
	n?: string;
	e?: string;
	d?: string;
	kid?: string;
};

type PublicJwk = JsonWebKey & {
	kty: string;
	n?: string;
	e?: string;
	kid: string;
	use?: string;
	alg?: string;
	key_ops?: string[];
};

let cachedKeysPromise: Promise<CachedKeys> | undefined;

export async function signJwt(
	privateKeyPemOrJwk: string,
	payload: JwtPayload,
	typ = "JWT",
): Promise<string> {
	const keys = await getKeys(privateKeyPemOrJwk);
	return jwt.sign(payload, { ...keys.privateJwk, kid: keys.kid }, {
		algorithm: "RS256",
		header: {
			alg: "RS256",
			kid: keys.kid,
			typ,
		},
	});
}

export async function exportJwks(privateKeyPemOrJwk: string): Promise<{ keys: PublicJwk[] }> {
	const keys = await getKeys(privateKeyPemOrJwk);
	return {
		keys: [
			{
				...keys.publicJwk,
				kid: keys.kid,
				use: "sig",
				alg: "RS256",
				key_ops: ["verify"],
			},
		],
	};
}

export async function verifyJwt(
	privateKeyPemOrJwk: string,
	token: string,
	options: { audience: string; issuer: string; tokenUse: "access" | "id" },
): Promise<JwtPayload> {
	const keys = await getKeys(privateKeyPemOrJwk);
	const decoded = await jwt.verify<JwtPayload>(token, keys.publicJwk, {
		algorithm: "RS256",
		throwError: true,
	});
	if (!decoded) {
		throw new Error("Invalid JWT");
	}

	const payload = decoded.payload;
	if (payload.iss !== options.issuer) {
		throw new Error("Unexpected issuer");
	}

	const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
	if (!audiences.includes(options.audience)) {
		throw new Error("Unexpected audience");
	}
	if (payload.token_use !== options.tokenUse) {
		throw new Error("Unexpected token use");
	}

	return payload;
}

async function getKeys(privateKeyPemOrJwk: string): Promise<CachedKeys> {
	if (!cachedKeysPromise) {
		cachedKeysPromise = loadKeys(privateKeyPemOrJwk);
	}
	return cachedKeysPromise;
}

async function loadKeys(privateKeyPemOrJwk: string): Promise<CachedKeys> {
	const privateJwk = await parsePrivateKey(privateKeyPemOrJwk);
	const { d, dp, dq, p, q, qi, oth, key_ops, use, alg, kid, ...publicJwk } = privateJwk;
	const resolvedKid =
		kid ??
		(await sha256base64Url(
			JSON.stringify({
				e: publicJwk.e,
				kty: publicJwk.kty,
				n: publicJwk.n,
			}),
		));

	return {
		privateJwk: { ...privateJwk, kid: resolvedKid },
		publicJwk: { ...(publicJwk as PublicJwk), kid: resolvedKid },
		kid: resolvedKid,
	};
}

async function parsePrivateKey(privateKeyPemOrJwk: string): Promise<PrivateJwk> {
	const trimmed = privateKeyPemOrJwk.trim();
	if (trimmed.startsWith("{")) {
		return JSON.parse(trimmed) as PrivateJwk;
	}

	const binary = atob(
		trimmed
			.replace("-----BEGIN PRIVATE KEY-----", "")
			.replace("-----END PRIVATE KEY-----", "")
			.replace(/\s+/gu, ""),
	);
	const bytes = new Uint8Array(binary.length);
	for (let index = 0; index < binary.length; index += 1) {
		bytes[index] = binary.charCodeAt(index);
	}

	const key = await crypto.subtle.importKey(
		"pkcs8",
		bytes,
		{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
		true,
		["sign"],
	);

	return (await crypto.subtle.exportKey("jwk", key)) as PrivateJwk;
}
