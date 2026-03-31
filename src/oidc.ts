import { OidcError, type OidcAuthorizationRequest } from "./types";

export function parseAuthorizationRequest(url: URL): OidcAuthorizationRequest {
	const scope = (url.searchParams.get("scope") ?? "")
		.split(/\s+/u)
		.map((value) => value.trim())
		.filter(Boolean);

	const request: OidcAuthorizationRequest = {
		clientId: url.searchParams.get("client_id") ?? "",
		redirectUri: url.searchParams.get("redirect_uri") ?? "",
		responseType: url.searchParams.get("response_type") ?? "",
		scope,
		state: url.searchParams.get("state"),
		nonce: url.searchParams.get("nonce"),
	};

	if (!request.clientId) {
		throw oidcError("invalid_request", "Missing client_id");
	}
	if (!request.redirectUri) {
		throw oidcError("invalid_request", "Missing redirect_uri");
	}
	if (request.responseType !== "code") {
		throw oidcError("unsupported_response_type", "Only response_type=code is supported");
	}
	if (!request.scope.includes("openid")) {
		throw oidcError("invalid_scope", "scope must include openid");
	}

	return request;
}

export function validateTokenRequest(params: URLSearchParams): void {
	if (params.get("grant_type") !== "authorization_code") {
		throw oidcError("unsupported_grant_type", "Only authorization_code is supported");
	}

	for (const field of ["code", "client_id", "client_secret", "redirect_uri"]) {
		if (!params.get(field)) {
			throw oidcError("invalid_request", `Missing ${field}`);
		}
	}
}

export function oidcError(
	error: string,
	errorDescription?: string,
	status = 400,
): OidcError {
	return new OidcError(error, errorDescription, status);
}

export function isOidcError(value: unknown): value is OidcError {
	return value instanceof OidcError;
}

export function scopeToEsaScope(scope: string[]): string {
	if (scope.includes("write")) {
		return "read write";
	}
	return "read";
}

export function userInfoScope(scope: string[]): string {
	return scope.join(" ");
}
