/* eslint-disable @typescript-eslint/no-explicit-any */
/**
 * Edge Config Setup Utility
 *
 * This utility helps set up and manage Edge Config for logging on Vercel.
 * It provides functions to initialize the Edge Config with proper structure
 * and manage log storage efficiently.
 */

interface EdgeConfigLogStore {
	logs: Array<{
		timestamp: string;
		level: string;
		service: string;
		message: string;
		[key: string]: any;
	}>;
	lastUpdated: string;
	maxSize: number;
}

interface EdgeConfigSetupResult {
	success: boolean;
	message: string;
	edgeConfigId?: string;
	keys?: string[];
}

/**
 * Initialize Edge Config with default log structure
 */
export async function initializeEdgeConfigForLogs(): Promise<EdgeConfigSetupResult> {
	if (!process.env.VERCEL_API_TOKEN) {
		return {
			success: false,
			message: "VERCEL_API_TOKEN environment variable is required",
		};
	}

	if (!process.env.EDGE_CONFIG_ID) {
		return {
			success: false,
			message: "EDGE_CONFIG_ID environment variable is required",
		};
	}

	const logTypes = ["api", "auth", "chat", "error", "general"];
	const initialLogStore: EdgeConfigLogStore = {
		logs: [],
		lastUpdated: new Date().toISOString(),
		maxSize: 1000,
	};

	try {
		// Initialize each log type in Edge Config
		const items = logTypes.map((type) => ({
			operation: "upsert" as const,
			key: `logs_${type}`,
			value: initialLogStore,
		}));

		const response = await fetch(
			`https://api.vercel.com/v1/edge-config/${process.env.EDGE_CONFIG_ID}/items`,
			{
				method: "PATCH",
				headers: {
					Authorization: `Bearer ${process.env.VERCEL_API_TOKEN}`,
					"Content-Type": "application/json",
				},
				body: JSON.stringify({ items }),
			}
		);

		if (!response.ok) {
			const errorText = await response.text();
			return {
				success: false,
				message: `Failed to initialize Edge Config: ${response.statusText} - ${errorText}`,
			};
		}

		return {
			success: true,
			message: "Edge Config initialized successfully for logging",
			edgeConfigId: process.env.EDGE_CONFIG_ID,
			keys: logTypes.map((type) => `logs_${type}`),
		};
	} catch (error) {
		return {
			success: false,
			message: `Error initializing Edge Config: ${
				error instanceof Error ? error.message : "Unknown error"
			}`,
		};
	}
}

/**
 * Check Edge Config health and structure
 */
export async function checkEdgeConfigHealth(): Promise<{
	healthy: boolean;
	issues: string[];
	recommendations: string[];
}> {
	const issues: string[] = [];
	const recommendations: string[] = [];

	// Check environment variables
	if (!process.env.EDGE_CONFIG) {
		issues.push("EDGE_CONFIG environment variable is not set");
		recommendations.push(
			"Set EDGE_CONFIG to your Edge Config connection string"
		);
	}

	if (!process.env.EDGE_CONFIG_ID) {
		issues.push("EDGE_CONFIG_ID environment variable is not set");
		recommendations.push("Set EDGE_CONFIG_ID to your Edge Config ID");
	}

	if (!process.env.VERCEL_API_TOKEN) {
		issues.push("VERCEL_API_TOKEN environment variable is not set");
		recommendations.push(
			"Set VERCEL_API_TOKEN for Edge Config write operations"
		);
	}

	// Check if running on Vercel
	if (!process.env.VERCEL) {
		recommendations.push("This setup is optimized for Vercel deployment");
	}

	// Try to connect to Edge Config
	try {
		if (process.env.EDGE_CONFIG) {
			const { createClient } = await import("@vercel/edge-config");
			const client = createClient(process.env.EDGE_CONFIG);

			// Test read operation
			await client.get("logs_api");
		}
	} catch (error) {
		issues.push(
			`Cannot connect to Edge Config: ${
				error instanceof Error ? error.message : "Unknown error"
			}`
		);
		recommendations.push(
			"Verify your EDGE_CONFIG connection string is correct"
		);
	}

	return {
		healthy: issues.length === 0,
		issues,
		recommendations,
	};
}

/**
 * Get Edge Config usage statistics
 */
export async function getEdgeConfigStats(): Promise<{
	totalLogs: number;
	logsByType: Record<string, number>;
	oldestLog?: string;
	newestLog?: string;
	storageEfficiency: number;
}> {
	let totalLogs = 0;
	const logsByType: Record<string, number> = {};
	let oldestLog: string | undefined;
	let newestLog: string | undefined;

	try {
		if (!process.env.EDGE_CONFIG) {
			throw new Error("EDGE_CONFIG not configured");
		}

		const { createClient } = await import("@vercel/edge-config");
		const client = createClient(process.env.EDGE_CONFIG);

		const logTypes = ["api", "auth", "chat", "error", "general"];

		for (const type of logTypes) {
			try {
				const logStore = (await client.get(
					`logs_${type}`
				)) as EdgeConfigLogStore | null;
				if (logStore?.logs) {
					const count = logStore.logs.length;
					logsByType[type] = count;
					totalLogs += count;

					// Find oldest and newest logs
					for (const log of logStore.logs) {
						if (!oldestLog || log.timestamp < oldestLog) {
							oldestLog = log.timestamp;
						}
						if (!newestLog || log.timestamp > newestLog) {
							newestLog = log.timestamp;
						}
					}
				} else {
					logsByType[type] = 0;
				}
			} catch (error) {
				console.warn(`Failed to get stats for ${type} logs:`, error);
				logsByType[type] = 0;
			}
		}

		// Calculate storage efficiency (how full the log stores are)
		const maxLogsPerType = 1000; // Default max size
		const maxTotalLogs = maxLogsPerType * logTypes.length;
		const storageEfficiency = (totalLogs / maxTotalLogs) * 100;

		return {
			totalLogs,
			logsByType,
			oldestLog,
			newestLog,
			storageEfficiency,
		};
	} catch (error) {
		console.error("Failed to get Edge Config stats:", error);
		return {
			totalLogs: 0,
			logsByType: {},
			storageEfficiency: 0,
		};
	}
}

/**
 * Clean up old logs from Edge Config to free space
 */
export async function cleanupOldLogs(daysToKeep: number = 7): Promise<{
	success: boolean;
	message: string;
	logsRemoved: number;
}> {
	if (!process.env.VERCEL_API_TOKEN || !process.env.EDGE_CONFIG_ID) {
		return {
			success: false,
			message:
				"VERCEL_API_TOKEN and EDGE_CONFIG_ID are required for cleanup",
			logsRemoved: 0,
		};
	}

	const cutoffDate = new Date();
	cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

	let totalLogsRemoved = 0;
	const logTypes = ["api", "auth", "chat", "error", "general"];

	try {
		if (!process.env.EDGE_CONFIG) {
			throw new Error("EDGE_CONFIG not configured");
		}

		const { createClient } = await import("@vercel/edge-config");
		const client = createClient(process.env.EDGE_CONFIG);

		const items = [];

		for (const type of logTypes) {
			const logStore = (await client.get(
				`logs_${type}`
			)) as EdgeConfigLogStore | null;

			if (logStore?.logs) {
				const originalCount = logStore.logs.length;
				const filteredLogs = logStore.logs.filter(
					(log) => new Date(log.timestamp) >= cutoffDate
				);

				if (filteredLogs.length < originalCount) {
					totalLogsRemoved += originalCount - filteredLogs.length;

					items.push({
						operation: "upsert" as const,
						key: `logs_${type}`,
						value: {
							...logStore,
							logs: filteredLogs,
							lastUpdated: new Date().toISOString(),
						},
					});
				}
			}
		}

		if (items.length > 0) {
			const response = await fetch(
				`https://api.vercel.com/v1/edge-config/${process.env.EDGE_CONFIG_ID}/items`,
				{
					method: "PATCH",
					headers: {
						Authorization: `Bearer ${process.env.VERCEL_API_TOKEN}`,
						"Content-Type": "application/json",
					},
					body: JSON.stringify({ items }),
				}
			);

			if (!response.ok) {
				throw new Error(`Cleanup failed: ${response.statusText}`);
			}
		}

		return {
			success: true,
			message: `Successfully cleaned up ${totalLogsRemoved} old logs`,
			logsRemoved: totalLogsRemoved,
		};
	} catch (error) {
		return {
			success: false,
			message: `Cleanup failed: ${
				error instanceof Error ? error.message : "Unknown error"
			}`,
			logsRemoved: 0,
		};
	}
}
