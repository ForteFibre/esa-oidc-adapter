import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { buildAuthorizeUrl, exchangeAuthorizationCode, fetchCurrentUser } from "./esa";
import { getConfig, type ResolvedConfig } from "./config";
import { exportJwks, signJwt, verifyJwt } from "./jwt";
import {
	authorizeQuerySchema,
	isOidcError,
	oidcErrorFromZod,
	oidcError,
	scopeToEsaScope,
	tokenRequestSchema,
	userInfoScope,
} from "./oidc";
import { TransientStore } from "./store";
import type {
	AdapterEnv,
	JwtPayload,
	OIDCUserInfoResponse,
	OidcTokenResponse,
	OidcUserClaims,
} from "./types";
import { currentEpochSeconds, errorDescription, randomToken } from "./utils";

const ACCESS_TOKEN_TTL_SECONDS = 3600;
const ID_TOKEN_TTL_SECONDS = 3600;

type AppEnv = {
	Bindings: AdapterEnv;
	Variables: {
		config: ResolvedConfig;
		store: TransientStore;
	};
};

const app = new Hono<AppEnv>();

app.use("*", async (c, next) => {
	const config = getConfig(c.env);
	c.set("config", config);
	c.set("store", new TransientStore(config.transientStore));
	await next();
});

app.onError((error, c) => {
	if (isOidcError(error)) {
		c.status(error.status as 400);
		return c.json({
			error: error.error,
			error_description: error.errorDescription,
		});
	}

	c.status(500);
	return c.json({
		error: "server_error",
		error_description: errorDescription(error),
	});
});

app.notFound((c) => c.json({ error: "not_found" }, 404));

app.get("/.well-known/openid-configuration", (c) => {
	const config = c.var.config;
	return c.json({
		issuer: config.issuer,
		authorization_endpoint: `${config.issuer}/authorize`,
		token_endpoint: `${config.issuer}/token`,
		userinfo_endpoint: `${config.issuer}/userinfo`,
		jwks_uri: `${config.issuer}/jwks.json`,
		response_types_supported: ["code"],
		grant_types_supported: ["authorization_code"],
		subject_types_supported: ["public"],
		id_token_signing_alg_values_supported: ["RS256"],
		token_endpoint_auth_methods_supported: ["client_secret_post"],
		scopes_supported: ["openid", "profile", "email", "read", "write"],
		claims_supported: ["sub", "name", "preferred_username", "email", "email_verified", "picture"],
	});
});

app.get(
	"/authorize",
	zValidator("query", authorizeQuerySchema, (result) => {
		if (!result.success) {
			throw oidcErrorFromZod(result.error);
		}
	}),
	async (c) => {
		const config = c.var.config;
		const store = c.var.store;
		const request = c.req.valid("query");

		if (request.clientId !== config.esaClientId) {
			throw oidcError("unauthorized_client", "Unknown client_id", 401);
		}

		const transientState = randomToken(24);
		await store.putSession(transientState, {
			clientId: request.clientId,
			redirectUri: request.redirectUri,
			oidcState: request.state,
			nonce: request.nonce,
			scope: request.scope,
			createdAt: Date.now(),
		});

		return c.redirect(
			buildAuthorizeUrl({
				team: config.esaTeam,
				clientId: config.esaClientId,
				redirectUri: config.callbackUrl,
				scope: scopeToEsaScope(request.scope),
				state: transientState,
			}),
			302,
		);
	},
);

app.get("/callback", async (c) => {
	const config = c.var.config;
	const store = c.var.store;
	const url = new URL(c.req.url);
	const transientState = url.searchParams.get("state");

	if (!transientState) {
		throw oidcError("invalid_request", "Missing callback state");
	}

	const session = await store.getSession(transientState);
	await store.deleteSession(transientState);
	if (!session) {
		throw oidcError("invalid_request", "Unknown or expired authorization session");
	}

	const target = new URL(session.redirectUri);
	if (url.searchParams.get("error")) {
		target.searchParams.set("error", "access_denied");
		if (session.oidcState) {
			target.searchParams.set("state", session.oidcState);
		}
		return c.redirect(target.toString(), 302);
	}

	const esaCode = url.searchParams.get("code");
	if (!esaCode) {
		target.searchParams.set("error", "server_error");
		target.searchParams.set("error_description", "esa callback did not include code");
		if (session.oidcState) {
			target.searchParams.set("state", session.oidcState);
		}
		return c.redirect(target.toString(), 302);
	}

	const adapterCode = randomToken(32);
	await store.putCode(adapterCode, {
		...session,
		esaCode,
	});

	target.searchParams.set("code", adapterCode);
	if (session.oidcState) {
		target.searchParams.set("state", session.oidcState);
	}

	return c.redirect(target.toString(), 302);
});

app.post(
	"/token",
	zValidator("form", tokenRequestSchema, (result) => {
		if (!result.success) {
			throw oidcErrorFromZod(result.error);
		}
	}),
	async (c) => {
		const config = c.var.config;
		const store = c.var.store;
		const {
			client_id: clientId,
			client_secret: clientSecret,
			redirect_uri: redirectUri,
			code,
		} = c.req.valid("form");

		if (clientId !== config.esaClientId || clientSecret !== config.esaClientSecret) {
			throw oidcError("invalid_client", "Client authentication failed", 401);
		}

		if (await store.isCodeUsed(code)) {
			throw oidcError("invalid_grant", "Authorization code has already been used");
		}

		const authCode = await store.getCode(code);
		if (!authCode) {
			throw oidcError("invalid_grant", "Authorization code is invalid or expired");
		}
		if (authCode.redirectUri !== redirectUri) {
			throw oidcError("invalid_grant", "redirect_uri mismatch");
		}

		await store.markCodeUsed(code);

		const esaToken = await exchangeAuthorizationCode({
			clientId: config.esaClientId,
			clientSecret: config.esaClientSecret,
			redirectUri: config.callbackUrl,
			code: authCode.esaCode,
		});
		const esaUser = await fetchCurrentUser(esaToken.access_token);
		const claims = mapClaims(esaUser);
		const { sub, ...claimFields } = claims;
		const now = currentEpochSeconds();

		const idTokenPayload: JwtPayload = {
			iss: config.issuer,
			sub,
			aud: clientId,
			exp: now + ID_TOKEN_TTL_SECONDS,
			iat: now,
			auth_time: now,
			nonce: authCode.nonce ?? undefined,
			token_use: "id",
			...claimFields,
		};

		const accessTokenPayload: JwtPayload = {
			iss: config.issuer,
			sub,
			aud: `${config.issuer}/userinfo`,
			exp: now + ACCESS_TOKEN_TTL_SECONDS,
			iat: now,
			nbf: now,
			jti: randomToken(16),
			scope: userInfoScope(authCode.scope),
			token_use: "access",
			...claimFields,
		};

		const response: OidcTokenResponse = {
			access_token: await signJwt(config.privateKeyPemOrJwk, accessTokenPayload, "at+jwt"),
			token_type: "Bearer",
			expires_in: ACCESS_TOKEN_TTL_SECONDS,
			id_token: await signJwt(config.privateKeyPemOrJwk, idTokenPayload),
			scope: authCode.scope.join(" "),
		};

		return c.json(response);
	},
);

app.get("/userinfo", async (c) => {
	const config = c.var.config;
	const authorization = c.req.header("authorization");

	if (!authorization?.startsWith("Bearer ")) {
		return c.json(
			{
				error: "invalid_token",
				error_description: "Missing bearer token",
			},
			401,
			{
				"www-authenticate": 'Bearer error="invalid_token"',
			},
		);
	}

	const payload = await verifyJwt(config.privateKeyPemOrJwk, authorization.slice("Bearer ".length), {
		audience: `${config.issuer}/userinfo`,
		issuer: config.issuer,
		tokenUse: "access",
	});

	const response: OIDCUserInfoResponse = {
		sub: payload.sub,
		name: payload.name,
		preferred_username: payload.preferred_username,
		email: payload.email,
		email_verified: payload.email_verified,
		picture: payload.picture,
	};

	return c.json(response);
});

app.get("/jwks.json", async (c) => c.json(await exportJwks(c.var.config.privateKeyPemOrJwk)));

app.get("/healthz", (c) => c.json({ ok: true }));

export default app;

function mapClaims(user: {
	id: number;
	name: string;
	screen_name: string;
	icon?: string;
	email?: string;
}): OidcUserClaims {
	return {
		sub: String(user.id),
		name: user.name,
		preferred_username: user.screen_name,
		picture: user.icon,
		email: user.email,
		email_verified: user.email ? false : undefined,
	};
}
