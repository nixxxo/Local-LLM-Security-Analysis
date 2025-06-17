import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { metricsCollector } from "@/lib/metrics";
import { withLogging } from "@/lib/middleware";

// Predefined API key for Grafana access
const GRAFANA_API_KEY = process.env.GRAFANA_API_KEY;

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

async function metricsHandler(request: NextRequest): Promise<NextResponse> {
	try {
		// Check authentication (API key or session)
		const authorized = await isAuthorized(request);
		if (!authorized) {
			return NextResponse.json(
				{ error: "Unauthorized - API key or valid session required" },
				{ status: 401 }
			);
		}

		const { searchParams } = new URL(request.url);
		const days = parseInt(searchParams.get("days") || "7");
		const format = searchParams.get("format") || "json";
		const realtime = searchParams.get("realtime") === "true";

		if (days < 1 || days > 30) {
			return NextResponse.json(
				{ error: "Days parameter must be between 1 and 30" },
				{ status: 400 }
			);
		}

		// Return different formats based on request
		switch (format) {
			case "prometheus":
				// Prometheus metrics format using prom-client
				const prometheusMetrics =
					await metricsCollector.getPrometheusMetrics();
				return new NextResponse(prometheusMetrics, {
					headers: {
						"Content-Type": "text/plain; charset=utf-8",
						"Cache-Control": "no-cache",
					},
				});

			case "grafana":
				// Grafana-compatible format
				const grafanaMetrics = metricsCollector.getGrafanaMetrics(days);
				return NextResponse.json(grafanaMetrics, {
					headers: {
						"Cache-Control": "no-cache",
					},
				});

			default:
				// Standard JSON format with all details
				const metrics = realtime
					? metricsCollector.getRealTimeMetrics()
					: metricsCollector.getMetrics(days);

				return NextResponse.json(
					{
						status: "success",
						data: {
							...metrics,
							auth: {
								...metrics.auth,
								uniqueUsers: Array.from(
									metrics.auth.uniqueUsers
								), // Convert Set to Array
							},
						},
						metadata: {
							generatedAt: new Date().toISOString(),
							daysIncluded: days,
							realtime,
						},
					},
					{
						headers: {
							"Cache-Control": "no-cache",
						},
					}
				);
		}
	} catch (error) {
		console.error("Metrics API error:", error);
		return NextResponse.json(
			{ error: "Failed to generate metrics" },
			{ status: 500 }
		);
	}
}

// Wrap the handler with logging
export const GET = withLogging(metricsHandler, "/api/metrics");
