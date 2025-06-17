/* eslint-disable @typescript-eslint/no-explicit-any */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { logger } from "./logger";

export function getClientIP(request: NextRequest): string {
	const forwardedFor = request.headers.get("x-forwarded-for");
	const realIp = request.headers.get("x-real-ip");
	const remoteAddr = request.headers.get("x-remote-addr");

	return forwardedFor
		? forwardedFor.split(",")[0].trim()
		: realIp || remoteAddr || "unknown";
}

export async function logRequest(
	request: NextRequest,
	response: NextResponse,
	endpoint: string
): Promise<void> {
	try {
		const session = await getServerSession(authOptions);
		const responseTime = Date.now() - (request as any)._startTime;

		const requestSize = request.headers.get("content-length")
			? parseInt(request.headers.get("content-length")!)
			: 0;

		const responseSize = response.headers.get("content-length")
			? parseInt(response.headers.get("content-length")!)
			: 0;

		logger.logApi({
			endpoint,
			method: request.method,
			userId: session?.user?.email || "anonymous",
			userEmail: session?.user?.email,
			ip: getClientIP(request),
			userAgent: request.headers.get("user-agent") || "unknown",
			statusCode: response.status,
			responseTime,
			requestSize,
			responseSize,
			metadata: {
				url: request.url,
				authenticated: !!session,
			},
		});
	} catch (error) {
		logger.logError("middleware", error as Error);
	}
}

export function withLogging<T extends any[]>(
	handler: (...args: T) => Promise<NextResponse>,
	endpoint: string
) {
	return async (...args: T): Promise<NextResponse> => {
		const request = args[0] as NextRequest;
		const startTime = Date.now();
		(request as any)._startTime = startTime;

		try {
			const response = await handler(...args);
			await logRequest(request, response, endpoint);
			return response;
		} catch (error) {
			logger.logError("api", error as Error, {
				endpoint,
				method: request.method,
			});

			// Create error response and log it
			const errorResponse = NextResponse.json(
				{ error: "Internal server error" },
				{ status: 500 }
			);
			await logRequest(request, errorResponse, endpoint);

			throw error;
		}
	};
}
