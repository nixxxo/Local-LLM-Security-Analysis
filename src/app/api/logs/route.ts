/* eslint-disable @typescript-eslint/no-explicit-any */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/app/api/auth/[...nextauth]/route";
import { readFileSync, readdirSync, existsSync } from "fs";
import { join } from "path";

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
		if (!session) {
			return NextResponse.json(
				{ error: "Unauthorized" },
				{ status: 401 }
			);
		}

		const { searchParams } = new URL(request.url);
		const limit = parseInt(searchParams.get("limit") || "100");
		const type = searchParams.get("type") || "all";

		const logs = await fetchRecentLogs(limit, type);

		return NextResponse.json({
			success: true,
			logs,
			total: logs.length,
		});
	} catch (error) {
		console.error("Error fetching logs:", error);
		return NextResponse.json(
			{ error: "Failed to fetch logs" },
			{ status: 500 }
		);
	}
}

async function fetchRecentLogs(
	limit: number = 100,
	type: string = "all"
): Promise<LogEntry[]> {
	const logDir = join(process.cwd(), "logs");
	const logs: LogEntry[] = [];

	if (!existsSync(logDir)) {
		return logs;
	}

	try {
		// Get all log files, sorted by date (newest first)
		const files = readdirSync(logDir)
			.filter((file) => file.endsWith(".jsonl"))
			.sort()
			.reverse();

		// Read files until we have enough logs
		for (const file of files) {
			if (logs.length >= limit) break;

			// Skip if filtering by type and file doesn't match
			if (type !== "all" && !file.startsWith(`${type}-`)) {
				continue;
			}

			try {
				const content = readFileSync(join(logDir, file), "utf-8");
				const lines = content
					.trim()
					.split("\n")
					.filter((line) => line.trim());

				for (const line of lines) {
					if (logs.length >= limit * 2) break; // Get more logs to ensure we have enough after sorting

					try {
						const logEntry = JSON.parse(line);

						// Transform log entry to match our interface
						const transformedLog: LogEntry = {
							timestamp: logEntry.timestamp,
							level: logEntry.level || "info",
							type:
								logEntry.service || logEntry.type || "general",
							message: logEntry.message || "",
							endpoint: logEntry.endpoint,
							method: logEntry.method,
							statusCode: logEntry.statusCode,
							userEmail: logEntry.userEmail,
							ip: logEntry.ip,
							responseTime: logEntry.responseTime,
							metadata: logEntry.metadata,
						};

						logs.push(transformedLog);
					} catch {
						console.warn(`Failed to parse log line: ${line}`);
					}
				}
			} catch (fileError) {
				console.warn(`Failed to read log file ${file}:`, fileError);
			}
		}
	} catch (error) {
		console.error("Error reading log directory:", error);
	}

	// Sort by timestamp (oldest first, so latest appear at bottom in UI)
	logs.sort(
		(a, b) =>
			new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
	);

	return logs.slice(0, limit);
}
