/* eslint-disable @typescript-eslint/no-explicit-any */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { logger } from "@/lib/logger";

export async function GET(request: NextRequest) {
	try {
		// Check authentication
		const session = await getServerSession(authOptions);
		if (!session?.user?.email) {
			return NextResponse.json(
				{ error: "Unauthorized" },
				{ status: 401 }
			);
		}

		const { searchParams } = new URL(request.url);
		const action = searchParams.get("action") || "health";

		let result;

		switch (action) {
			case "health":
				result = await logger.healthCheck();
				break;

			case "urls":
				result = {
					gistUrls: logger.getGistUrls(),
					message: "GitHub Gist URLs for log access",
				};
				break;

			case "stats":
				result = {
					gistStats: await logger.getGistStats(),
					message: "GitHub Gist storage statistics",
				};
				break;

			case "flush":
				await logger.flush();
				result = {
					success: true,
					message: "Log queue flushed successfully",
				};
				break;

			default:
				return NextResponse.json(
					{
						error: "Invalid action. Use: health, urls, stats, or flush",
					},
					{ status: 400 }
				);
		}

		// Log this API access
		logger.logApi({
			method: request.method,
			endpoint: "/api/gist-logs",
			statusCode: 200,
			userEmail: session.user.email,
			ip: request.headers.get("x-forwarded-for") || "unknown",
			responseTime:
				Date.now() - ((request as any)._startTime || Date.now()),
			metadata: { action },
		});

		return NextResponse.json({
			success: true,
			data: result,
		});
	} catch (error) {
		console.error("GitHub Gist API error:", error);

		logger.logError("api", error as Error, {
			endpoint: "/api/gist-logs",
			method: "GET",
		});

		return NextResponse.json(
			{ error: "GitHub Gist operation failed" },
			{ status: 500 }
		);
	}
}

export async function POST(request: NextRequest) {
	try {
		// Check authentication
		const session = await getServerSession(authOptions);
		if (!session?.user?.email) {
			return NextResponse.json(
				{ error: "Unauthorized" },
				{ status: 401 }
			);
		}

		const body = await request.json();
		const { action } = body;

		let result;

		switch (action) {
			case "flush":
				await logger.flush();
				result = {
					success: true,
					message: "Log queue flushed successfully",
				};
				break;

			case "test":
				// Test logging functionality
				logger.logInfo("test", "GitHub Gist logging test", {
					testTimestamp: new Date().toISOString(),
					user: session.user.email,
				});

				result = {
					success: true,
					message: "Test log entry created",
					gistUrls: logger.getGistUrls(),
				};
				break;

			default:
				return NextResponse.json(
					{ error: "Invalid action. Use: flush or test" },
					{ status: 400 }
				);
		}

		// Log this API access
		logger.logApi({
			method: request.method,
			endpoint: "/api/gist-logs",
			statusCode: 200,
			userEmail: session.user.email,
			ip: request.headers.get("x-forwarded-for") || "unknown",
			responseTime:
				Date.now() - ((request as any)._startTime || Date.now()),
			metadata: { action },
		});

		return NextResponse.json({
			success: true,
			data: result,
		});
	} catch (error) {
		console.error("GitHub Gist API error:", error);

		logger.logError("api", error as Error, {
			endpoint: "/api/gist-logs",
			method: "POST",
		});

		return NextResponse.json(
			{ error: "GitHub Gist operation failed" },
			{ status: 500 }
		);
	}
}
