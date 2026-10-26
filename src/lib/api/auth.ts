import { NextResponse } from "next/server";
import { getCurrentUser } from "@/lib/auth/cookies";
import { authenticateApiKeyValue, hasScope } from "@/lib/api/key-auth";
import type { ApiAuthResult } from "@/lib/api/key-auth-types";

export type { ApiAuthResult };

export async function authenticateApiKey(
	env: CloudflareEnv,
	authorization: string | null,
): Promise<ApiAuthResult | null> {
	if (!authorization?.startsWith("Bearer ")) return null;
	return authenticateApiKeyValue(env, authorization.slice(7));
}

/**
 * The send API also takes the key the way other mail APIs do: `Authorization: Bearer <key>`,
 * a bare key in `Authorization`, or an `X-API-Key` header. HTTP auth schemes other than
 * Bearer (Basic, Digest, ...) are not keys and are rejected.
 */
export async function authenticateApiKeyFromHeaders(
	env: CloudflareEnv,
	headers: Headers,
): Promise<ApiAuthResult | null> {
	const authorization = headers.get("authorization")?.trim();
	if (authorization) {
		if (authorization.startsWith("Bearer ")) return authenticateApiKeyValue(env, authorization.slice(7));
		if (!/\s/.test(authorization)) return authenticateApiKeyValue(env, authorization);
		return null;
	}
	const apiKey = headers.get("x-api-key")?.trim();
	return apiKey ? authenticateApiKeyValue(env, apiKey) : null;
}

export const requireScope = hasScope;

/**
 * Session auth for route handlers. `requireUser` throws a bare Error, which Next turns into
 * a 500; this returns a proper 401 response instead so unauthenticated callers get the right
 * status.
 */
export async function requireSessionUser(env: CloudflareEnv, request: Request) {
	const user = await getCurrentUser(env, request);
	if (!user) {
		return { user: null, error: NextResponse.json({ error: "Unauthorized" }, { status: 401 }) } as const;
	}
	return { user, error: null } as const;
}
