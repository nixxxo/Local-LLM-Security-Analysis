/* eslint-disable @typescript-eslint/no-explicit-any */
import { writeFileSync, existsSync, mkdirSync, statSync, renameSync } from "fs";
import { join } from "path";

// Edge Config imports - only available on Vercel
let EdgeConfig: any = null;
let edgeConfigClient: any = null;

// Initialize Edge Config if available
try {
	if (process.env.VERCEL || process.env.EDGE_CONFIG) {
		EdgeConfig = await import("@vercel/edge-config");
		edgeConfigClient = EdgeConfig.createClient(process.env.EDGE_CONFIG);
	}
} catch {
	// Edge Config not available - will use file system
	console.log("Edge Config not available, using file system logging");
}

export interface LogEvent {
	timestamp: string;
	level: "INFO" | "WARN" | "ERROR" | "DEBUG";
	service: string;
	endpoint?: string;
	userId?: string;
	userEmail?: string;
	sessionId?: string;
	ip?: string;
	userAgent?: string;
	method?: string;
	statusCode?: number;
	responseTime?: number;
	requestSize?: number;
	responseSize?: number;
	message: string;
	metadata?: Record<string, any>;
	error?: string;
}

export interface ChatLogEvent extends LogEvent {
	chatId?: string;
	messageCount?: number;
	model?: string;
	temperature?: number;
	tokens?: {
		prompt: number;
		completion: number;
		total: number;
	};
}

export interface AuthLogEvent extends LogEvent {
	action: "LOGIN" | "LOGOUT" | "LOGIN_FAILED" | "SIGNUP";
	provider?: string;
}

interface EdgeConfigLogStore {
	logs: LogEvent[];
	lastUpdated: string;
	maxSize: number;
}

class Logger {
	private logDir: string;
	private maxFileSize: number = 50 * 1024 * 1024; // 50MB
	private maxFiles: number = 10;
	private isVercel: boolean;
	private maxEdgeConfigLogs: number = 1000; // Maximum logs to store in Edge Config

	constructor() {
		this.logDir = join(process.cwd(), "logs");
		this.isVercel = !!(process.env.VERCEL || process.env.EDGE_CONFIG);

		if (!this.isVercel) {
			this.ensureLogDirectory();
		}
	}

	private ensureLogDirectory(): void {
		if (!existsSync(this.logDir)) {
			mkdirSync(this.logDir, { recursive: true });
		}
	}

	private getLogFilePath(type: string): string {
		const date = new Date().toISOString().split("T")[0];
		return join(this.logDir, `${type}-${date}.jsonl`);
	}

	private rotateLogFile(filePath: string): void {
		if (!existsSync(filePath)) return;

		const stats = statSync(filePath);
		if (stats.size < this.maxFileSize) return;

		// Rotate files
		for (let i = this.maxFiles - 1; i > 0; i--) {
			const oldFile = `${filePath}.${i}`;
			const newFile = `${filePath}.${i + 1}`;
			if (existsSync(oldFile)) {
				renameSync(oldFile, newFile);
			}
		}

		renameSync(filePath, `${filePath}.1`);
	}

	private async writeToEdgeConfig(
		type: string,
		logEvent: LogEvent
	): Promise<void> {
		if (!edgeConfigClient) {
			throw new Error("Edge Config client not initialized");
		}

		try {
			// Get existing logs for this type
			const existingData = (await edgeConfigClient.get(
				`logs_${type}`
			)) as EdgeConfigLogStore | null;

			const logStore: EdgeConfigLogStore = existingData || {
				logs: [],
				lastUpdated: new Date().toISOString(),
				maxSize: this.maxEdgeConfigLogs,
			};

			// Add new log
			logStore.logs.push(logEvent);
			logStore.lastUpdated = new Date().toISOString();

			// Rotate logs if we exceed max size (keep most recent)
			if (logStore.logs.length > this.maxEdgeConfigLogs) {
				logStore.logs = logStore.logs
					.sort(
						(a, b) =>
							new Date(b.timestamp).getTime() -
							new Date(a.timestamp).getTime()
					)
					.slice(0, this.maxEdgeConfigLogs);
			}

			// Update Edge Config
			// Note: This requires a write API call to Edge Config
			// In production, you might want to batch these updates
			await this.updateEdgeConfig(`logs_${type}`, logStore);
		} catch (error) {
			console.error(
				`Failed to write to Edge Config for type ${type}:`,
				error
			);
			// Fallback to console logging
			console.log(
				`[${logEvent.level}] ${logEvent.service}: ${logEvent.message}`
			);
		}
	}

	private async updateEdgeConfig(key: string, value: any): Promise<void> {
		// Edge Config updates require API calls to Vercel's REST API
		// This is a placeholder for the actual implementation
		// In practice, you'd need to use the Vercel API with proper authentication

		if (!process.env.VERCEL_API_TOKEN) {
			console.warn(
				"VERCEL_API_TOKEN not set - cannot update Edge Config"
			);
			return;
		}

		try {
			const response = await fetch(
				`https://api.vercel.com/v1/edge-config/${process.env.EDGE_CONFIG_ID}/items`,
				{
					method: "PATCH",
					headers: {
						Authorization: `Bearer ${process.env.VERCEL_API_TOKEN}`,
						"Content-Type": "application/json",
					},
					body: JSON.stringify({
						items: [
							{
								operation: "upsert",
								key,
								value,
							},
						],
					}),
				}
			);

			if (!response.ok) {
				throw new Error(
					`Edge Config update failed: ${response.statusText}`
				);
			}
		} catch (error) {
			console.error("Failed to update Edge Config:", error);
		}
	}

	private writeLogToFile(type: string, logEvent: LogEvent): void {
		try {
			const filePath = this.getLogFilePath(type);
			this.rotateLogFile(filePath);

			const logLine = JSON.stringify(logEvent) + "\n";
			writeFileSync(filePath, logLine, { flag: "a" });
		} catch (error) {
			console.error("Failed to write log to file:", error);
		}
	}

	private async writeLog(type: string, logEvent: LogEvent): Promise<void> {
		try {
			// Choose storage method based on environment
			if (this.isVercel && edgeConfigClient) {
				await this.writeToEdgeConfig(type, logEvent);
			} else {
				this.writeLogToFile(type, logEvent);
			}

			// Update Prometheus metrics
			if (typeof window === "undefined") {
				// Only on server side
				try {
					// Use dynamic import to avoid circular dependencies
					import("./metrics")
						.then(({ metricsCollector }) => {
							metricsCollector.updatePrometheusMetrics(logEvent);
						})
						.catch(() => {
							// Ignore metrics update errors to prevent circular dependencies
						});
				} catch {
					// Ignore metrics update errors to prevent circular dependencies
				}
			}

			// Also log to console in development
			if (process.env.NODE_ENV === "development") {
				console.log(
					`[${logEvent.level}] ${logEvent.service}: ${logEvent.message}`
				);
			}
		} catch (error) {
			console.error("Failed to write log:", error);
		}
	}

	// Public method to get logs from Edge Config
	async getLogsFromEdgeConfig(type: string = "all"): Promise<LogEvent[]> {
		if (!edgeConfigClient) {
			return [];
		}

		try {
			if (type === "all") {
				// Get all log types
				const [apiLogs, authLogs, chatLogs, errorLogs, generalLogs] =
					await Promise.all([
						edgeConfigClient.get(
							"logs_api"
						) as Promise<EdgeConfigLogStore | null>,
						edgeConfigClient.get(
							"logs_auth"
						) as Promise<EdgeConfigLogStore | null>,
						edgeConfigClient.get(
							"logs_chat"
						) as Promise<EdgeConfigLogStore | null>,
						edgeConfigClient.get(
							"logs_error"
						) as Promise<EdgeConfigLogStore | null>,
						edgeConfigClient.get(
							"logs_general"
						) as Promise<EdgeConfigLogStore | null>,
					]);

				const allLogs: LogEvent[] = [];
				[apiLogs, authLogs, chatLogs, errorLogs, generalLogs].forEach(
					(logStore) => {
						if (logStore?.logs) {
							allLogs.push(...logStore.logs);
						}
					}
				);

				// Sort by timestamp
				return allLogs.sort(
					(a, b) =>
						new Date(b.timestamp).getTime() -
						new Date(a.timestamp).getTime()
				);
			} else {
				const logStore = (await edgeConfigClient.get(
					`logs_${type}`
				)) as EdgeConfigLogStore | null;
				return logStore?.logs || [];
			}
		} catch (error) {
			console.error("Failed to get logs from Edge Config:", error);
			return [];
		}
	}

	logApi(event: Partial<LogEvent>): void {
		const logEvent: LogEvent = {
			timestamp: new Date().toISOString(),
			level: "INFO",
			service: "api",
			message: `${event.method} ${event.endpoint}`,
			...event,
		};

		this.writeLog("api", logEvent);
	}

	logAuth(event: Partial<AuthLogEvent>): void {
		const logEvent: AuthLogEvent = {
			timestamp: new Date().toISOString(),
			level: "INFO",
			service: "auth",
			action: event.action || "LOGIN",
			message: `User ${event.action?.toLowerCase()} attempt`,
			...event,
		};

		this.writeLog("auth", logEvent);
	}

	logChat(event: Partial<ChatLogEvent>): void {
		const logEvent: ChatLogEvent = {
			timestamp: new Date().toISOString(),
			level: "INFO",
			service: "chat",
			message: `Chat interaction`,
			...event,
		};

		this.writeLog("chat", logEvent);
	}

	logError(
		service: string,
		error: Error | string,
		metadata?: Record<string, any>
	): void {
		const logEvent: LogEvent = {
			timestamp: new Date().toISOString(),
			level: "ERROR",
			service,
			message: error instanceof Error ? error.message : error,
			error: error instanceof Error ? error.stack : undefined,
			metadata,
		};

		this.writeLog("error", logEvent);
	}

	logInfo(
		service: string,
		message: string,
		metadata?: Record<string, any>
	): void {
		const logEvent: LogEvent = {
			timestamp: new Date().toISOString(),
			level: "INFO",
			service,
			message,
			metadata,
		};

		this.writeLog("general", logEvent);
	}

	// Utility method to check if running on Vercel
	isRunningOnVercel(): boolean {
		return this.isVercel;
	}
}

export const logger = new Logger();
