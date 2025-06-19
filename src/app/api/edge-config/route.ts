import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import {
	initializeEdgeConfigForLogs,
	checkEdgeConfigHealth,
	getEdgeConfigStats,
	cleanupOldLogs,
} from "@/lib/edge-config-setup";

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
		const action = searchParams.get("action") || "health";

		switch (action) {
			case "health":
				const health = await checkEdgeConfigHealth();
				return NextResponse.json({
					success: true,
					data: health,
				});

			case "stats":
				const stats = await getEdgeConfigStats();
				return NextResponse.json({
					success: true,
					data: stats,
				});

			default:
				return NextResponse.json(
					{ error: "Invalid action. Use 'health' or 'stats'" },
					{ status: 400 }
				);
		}
	} catch (error) {
		console.error("Edge Config API error:", error);
		return NextResponse.json(
			{ error: "Failed to process Edge Config request" },
			{ status: 500 }
		);
	}
}

export async function POST(request: NextRequest) {
	try {
		// Check authentication
		const session = await getServerSession(authOptions);
		if (!session) {
			return NextResponse.json(
				{ error: "Unauthorized" },
				{ status: 401 }
			);
		}

		const body = await request.json();
		const { action, daysToKeep } = body;

		switch (action) {
			case "initialize":
				const initResult = await initializeEdgeConfigForLogs();
				return NextResponse.json({
					success: initResult.success,
					message: initResult.message,
					data: initResult,
				});

			case "cleanup":
				const cleanupResult = await cleanupOldLogs(daysToKeep || 7);
				return NextResponse.json({
					success: cleanupResult.success,
					message: cleanupResult.message,
					data: cleanupResult,
				});

			default:
				return NextResponse.json(
					{ error: "Invalid action. Use 'initialize' or 'cleanup'" },
					{ status: 400 }
				);
		}
	} catch (error) {
		console.error("Edge Config POST API error:", error);
		return NextResponse.json(
			{ error: "Failed to process Edge Config request" },
			{ status: 500 }
		);
	}
}
