/* eslint-disable @typescript-eslint/no-explicit-any */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { logger } from "@/lib/logger";

interface LogEntry {
	timestamp: string;
	level: string;
	type: string;
	message: string;
	endpoint?: string;
	method?: string;
	statusCode?: number;
	userEmail?: string;
	ip?: string;
	responseTime?: number;
	metadata?: any;
}

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

		// Get query parameters
		const { searchParams } = new URL(request.url);
		const limit = parseInt(searchParams.get("limit") || "100");
		const type = searchParams.get("type") || "all";

		// Fetch logs from GitHub Gist
		const logs = await fetchLogsFromGist(limit, type);

		// Log this API access
		logger.logApi({
			method: request.method,
			endpoint: "/api/logs",
			statusCode: 200,
			userEmail: session.user.email,
			ip: request.headers.get("x-forwarded-for") || "unknown",
			responseTime:
				Date.now() - ((request as any)._startTime || Date.now()),
			metadata: { type, limit },
		});

		return NextResponse.json({
			success: true,
			data: {
				logs,
				total: logs.length,
				type,
				limit,
			},
		});
	} catch (error) {
		console.error("Error fetching logs:", error);

		// Log the error
		logger.logError("api", error as Error, {
			endpoint: "/api/logs",
			method: "GET",
		});

		return NextResponse.json(
			{ error: "Failed to fetch logs" },
			{ status: 500 }
		);
	}
}

async function fetchLogsFromGist(
	limit: number = 100,
	type: string = "all"
): Promise<LogEntry[]> {
	try {
		const logs = await logger.getLogsFromGist(type);

		// Transform logs to match our interface
		const transformedLogs: LogEntry[] = logs.map((logEntry) => ({
			timestamp: logEntry.timestamp,
			level: logEntry.level || "info",
			type: logEntry.service || "general",
			message: logEntry.message || "",
			endpoint: logEntry.endpoint,
			method: logEntry.method,
			statusCode: logEntry.statusCode,
			userEmail: logEntry.userEmail,
			ip: logEntry.ip,
			responseTime: logEntry.responseTime,
			metadata: logEntry.metadata,
		}));

		// Sort by timestamp (newest first, then slice to limit)
		transformedLogs.sort(
			(a, b) =>
				new Date(b.timestamp).getTime() -
				new Date(a.timestamp).getTime()
		);

		return transformedLogs.slice(0, limit);
	} catch (error) {
		console.error("Error fetching logs from GitHub Gist:", error);
		return [];
	}
}
