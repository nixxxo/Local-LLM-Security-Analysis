import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { metricsCollector } from "@/lib/metrics";

// Predefined API key for Grafana access
const GRAFANA_API_KEY =
	process.env.GRAFANA_API_KEY || "grafana-metrics-key-2024";

async function isAuthorized(request: NextRequest): Promise<boolean> {
	// Check for API key in Authorization header (for Grafana)
	const authHeader = request.headers.get("authorization");
	if (authHeader) {
		const apiKey = authHeader.replace("Bearer ", "").replace("Basic ", "");
		if (apiKey === GRAFANA_API_KEY) {
			return true;
		}
	}

	// Check for API key in query params (alternative for Grafana)
	const { searchParams } = new URL(request.url);
	const queryApiKey = searchParams.get("api_key");
	if (queryApiKey === GRAFANA_API_KEY) {
		return true;
	}

	// Fallback to session authentication for dashboard access
	try {
		const session = await getServerSession(authOptions);
		return !!session;
	} catch {
		return false;
	}
}

export async function GET(request: NextRequest): Promise<NextResponse> {
	try {
		// Check authentication (API key or session)
		const authorized = await isAuthorized(request);
		if (!authorized) {
			return NextResponse.json(
				{ error: "Unauthorized - API key or valid session required" },
				{ status: 401 }
			);
		}

		// Get Prometheus metrics
		const prometheusMetrics = await metricsCollector.getPrometheusMetrics();

		return new NextResponse(prometheusMetrics, {
			headers: {
				"Content-Type": "text/plain; charset=utf-8",
				"Cache-Control": "no-cache, no-store, must-revalidate",
				Pragma: "no-cache",
				Expires: "0",
			},
		});
	} catch (error) {
		console.error("Prometheus metrics error:", error);
		return new NextResponse("# Error generating metrics\n", {
			status: 500,
			headers: { "Content-Type": "text/plain; charset=utf-8" },
		});
	}
}
