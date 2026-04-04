import { z } from 'zod';
import { OidcError, type OidcAuthorizationRequest } from './types';

type OidcValidationError = {
	issues: Array<{
		path: PropertyKey[];
		message: string;
	}>;
};

const requiredString = (field: string) =>
	z.preprocess((value) => (typeof value === 'string' ? value : ''), z.string().min(1, { message: `Missing ${field}` }));

const authorizeQueryInputSchema = z.object({
	client_id: requiredString('client_id'),
	redirect_uri: requiredString('redirect_uri'),
	response_type: z
		.preprocess((value) => (typeof value === 'string' ? value : ''), z.string())
		.refine((value) => value === 'code', {
			message: 'Only response_type=code is supported',
		}),
	scope: z
		.preprocess((value) => (typeof value === 'string' ? value : ''), z.string())
		.transform(splitScope)
		.refine((value) => value.includes('openid'), {
			message: 'scope must include openid',
		}),
	state: z.string().optional(),
	nonce: z.string().optional(),
});

export const authorizeQuerySchema = authorizeQueryInputSchema.transform(
	(value): OidcAuthorizationRequest => ({
		clientId: value.client_id,
		redirectUri: value.redirect_uri,
		responseType: value.response_type,
		scope: value.scope,
		state: value.state ?? null,
		nonce: value.nonce ?? null,
	}),
);

export const tokenRequestSchema = z.object({
	grant_type: z
		.preprocess((value) => (typeof value === 'string' ? value : ''), z.string())
		.refine((value) => value === 'authorization_code', {
			message: 'Only authorization_code is supported',
		}),
	code: requiredString('code'),
	client_id: requiredString('client_id'),
	client_secret: requiredString('client_secret'),
	redirect_uri: requiredString('redirect_uri'),
});

export function oidcErrorFromZod(error: OidcValidationError): OidcError {
	const issue = error.issues[0];
	const field = issue?.path[0];

	console.error('Validation error:', error);

	if (field === 'response_type') {
		return oidcError('unsupported_response_type', 'Only response_type=code is supported');
	}
	if (field === 'grant_type') {
		return oidcError('unsupported_grant_type', 'Only authorization_code is supported');
	}
	if (field === 'scope') {
		return oidcError('invalid_scope', 'scope must include openid');
	}
	if (typeof issue?.message === 'string' && issue.message.startsWith('Missing ')) {
		return oidcError('invalid_request', issue.message);
	}

	return oidcError('invalid_request', issue?.message ?? 'Invalid request');
}

export function oidcError(error: string, errorDescription?: string, status = 400): OidcError {
	return new OidcError(error, errorDescription, status);
}

export function isOidcError(value: unknown): value is OidcError {
	return value instanceof OidcError;
}

export function scopeToEsaScope(scope: string[]): string {
	if (scope.includes('write')) {
		return 'read write';
	}
	return 'read';
}

export function userInfoScope(scope: string[]): string {
	return scope.join(' ');
}

function splitScope(value: string): string[] {
	return value
		.split(/\s+/u)
		.map((entry) => entry.trim())
		.filter(Boolean);
}
