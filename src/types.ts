export interface AdapterEnv {
	ESA_TEAM: string;
	ESA_CLIENT_ID: string;
	ESA_CLIENT_SECRET: string;
	ISSUER_URL: string;
	OIDC_JWT_PRIVATE_KEY: string;
	TRANSIENT_STORE: KVNamespace;
}

export interface OidcAuthorizationRequest {
	clientId: string;
	redirectUri: string;
	responseType: string;
	scope: string[];
	state: string | null;
	nonce: string | null;
}

export class OidcError extends Error {
	constructor(
		public readonly error: string,
		public readonly errorDescription?: string,
		public readonly status = 400,
	) {
		super(errorDescription ?? error);
		this.name = "OidcError";
	}
}

export interface TransientAuthSession {
	clientId: string;
	redirectUri: string;
	oidcState: string | null;
	nonce: string | null;
	scope: string[];
	createdAt: number;
}

export interface TransientAuthCode extends TransientAuthSession {
	esaCode: string;
}

export interface EsaTokenResponse {
	access_token: string;
	token_type: string;
	scope: string;
	created_at: number;
}

export interface EsaUserProfile {
	id: number;
	name: string;
	screen_name: string;
	icon?: string;
	email?: string;
	created_at?: string;
	updated_at?: string;
}

export interface OidcUserClaims {
	sub: string;
	name?: string;
	preferred_username?: string;
	email?: string;
	email_verified?: boolean;
	picture?: string;
}

export interface OidcTokenResponse {
	access_token: string;
	token_type: "Bearer";
	expires_in: number;
	id_token: string;
	scope: string;
}

export interface OIDCUserInfoResponse {
	sub: string;
	name?: string;
	preferred_username?: string;
	email?: string;
	email_verified?: boolean;
	picture?: string;
}

export interface JwtPayload {
	iss: string;
	sub: string;
	aud: string | string[];
	exp: number;
	iat: number;
	nbf?: number;
	jti?: string;
	nonce?: string;
	auth_time?: number;
	scope?: string;
	token_use?: "id" | "access";
	name?: string;
	preferred_username?: string;
	email?: string;
	email_verified?: boolean;
	picture?: string;
}
