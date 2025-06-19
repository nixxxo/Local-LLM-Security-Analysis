/* eslint-disable @typescript-eslint/no-explicit-any */

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

interface GistLogStore {
	logs: LogEvent[];
	lastUpdated: string;
	maxSize: number;
	version: string;
}

interface GistFile {
	filename: string;
	content: string;
}

interface GistResponse {
	id: string;
	files: Record<string, GistFile>;
	updated_at: string;
}

class Logger {
	private githubToken: string;
	private gistIds: Record<string, string> = {};
	private maxLogsPerGist: number = 1000;
	private batchSize: number = 10;
	private logQueue: Array<{ type: string; event: LogEvent }> = [];
	private flushTimeout: NodeJS.Timeout | null = null;
	private maxLogAge: number = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds

	constructor() {
		this.githubToken = process.env.GITHUB_TOKEN || "";

		// Initialize gist IDs from environment variables
		this.gistIds = {
			api: process.env.GITHUB_GIST_API || "",
			auth: process.env.GITHUB_GIST_AUTH || "",
			chat: process.env.GITHUB_GIST_CHAT || "",
			error: process.env.GITHUB_GIST_ERROR || "",
			general: process.env.GITHUB_GIST_GENERAL || "",
		};

		if (!this.githubToken) {
			console.warn(
				"GITHUB_TOKEN not set - logging will use console fallback"
			);
		}
	}

	private async createGist(
		type: string,
		description: string
	): Promise<string> {
		if (!this.githubToken) {
			throw new Error("GitHub token not configured");
		}

		const initialLogStore: GistLogStore = {
			logs: [],
			lastUpdated: new Date().toISOString(),
			maxSize: this.maxLogsPerGist,
			version: "1.0.0",
		};

		const response = await fetch("https://api.github.com/gists", {
			method: "POST",
			headers: {
				Authorization: `Bearer ${this.githubToken}`,
				"Content-Type": "application/json",
				"User-Agent": "local-llm-logger",
			},
			body: JSON.stringify({
				description,
				public: false,
				files: {
					[`${type}-logs.json`]: {
						content: JSON.stringify(initialLogStore, null, 2),
					},
				},
			}),
		});

		if (!response.ok) {
			const error = await response.text();
			throw new Error(
				`Failed to create gist: ${response.statusText} - ${error}`
			);
		}

		const gist = (await response.json()) as GistResponse;
		return gist.id;
	}

	private async getGistContent(
		gistId: string,
		filename: string
	): Promise<GistLogStore | null> {
		if (!this.githubToken || !gistId) {
			return null;
		}

		try {
			const response = await fetch(
				`https://api.github.com/gists/${gistId}`,
				{
					headers: {
						Authorization: `Bearer ${this.githubToken}`,
						"User-Agent": "local-llm-logger",
					},
				}
			);

			if (!response.ok) {
				console.warn(
					`Failed to fetch gist ${gistId}: ${response.statusText}`
				);
				return null;
			}

			const gist = (await response.json()) as GistResponse;
			const file = gist.files[filename];

			if (!file) {
				console.warn(`File ${filename} not found in gist ${gistId}`);
				return null;
			}

			return JSON.parse(file.content) as GistLogStore;
		} catch (error) {
			console.error(`Error reading gist ${gistId}:`, error);
			return null;
		}
	}

	private cleanupLogs(logs: LogEvent[]): LogEvent[] {
		const now = Date.now();
		const cutoffTime = now - this.maxLogAge;

		// Remove logs older than maxLogAge
		const recentLogs = logs.filter((log) => {
			const logTime = new Date(log.timestamp).getTime();
			return logTime >= cutoffTime;
		});

		// Sort by timestamp (newest first)
		recentLogs.sort(
			(a, b) =>
				new Date(b.timestamp).getTime() -
				new Date(a.timestamp).getTime()
		);

		// Limit to maxLogsPerGist (keep most recent)
		if (recentLogs.length > this.maxLogsPerGist) {
			const removedCount = recentLogs.length - this.maxLogsPerGist;
			console.log(
				`📦 Rotating logs: keeping ${this.maxLogsPerGist} most recent, removing ${removedCount} old logs`
			);
			return recentLogs.slice(0, this.maxLogsPerGist);
		}

		return recentLogs;
	}

	private async updateGist(
		gistId: string,
		filename: string,
		logStore: GistLogStore
	): Promise<void> {
		if (!this.githubToken || !gistId) {
			throw new Error("GitHub token or gist ID not configured");
		}

		try {
			const response = await fetch(
				`https://api.github.com/gists/${gistId}`,
				{
					method: "PATCH",
					headers: {
						Authorization: `Bearer ${this.githubToken}`,
						"Content-Type": "application/json",
						"User-Agent": "local-llm-logger",
					},
					body: JSON.stringify({
						files: {
							[filename]: {
								content: JSON.stringify(logStore, null, 2),
							},
						},
					}),
				}
			);

			if (!response.ok) {
				const error = await response.text();
				throw new Error(
					`Failed to update gist: ${response.statusText} - ${error}`
				);
			}
		} catch (error) {
			console.error(`Error updating gist ${gistId}:`, error);
			throw error;
		}
	}

	private async ensureGistExists(type: string): Promise<string> {
		let gistId = this.gistIds[type];

		if (!gistId) {
			// Create new gist only once per type
			const description = `Local LLM App - ${
				type.charAt(0).toUpperCase() + type.slice(1)
			} Logs`;
			gistId = await this.createGist(type, description);
			this.gistIds[type] = gistId;

			console.log(`✅ Created new gist for ${type} logs: ${gistId}`);
			console.log(
				`💡 Add this to your environment variables: GITHUB_GIST_${type.toUpperCase()}=${gistId}`
			);
			console.log(`🔗 View logs at: https://gist.github.com/${gistId}`);
		}

		return gistId;
	}

	private async writeToGist(type: string, logEvent: LogEvent): Promise<void> {
		try {
			const gistId = await this.ensureGistExists(type);
			const filename = `${type}-logs.json`;

			// Get existing logs
			const existingLogStore = await this.getGistContent(
				gistId,
				filename
			);

			const logStore: GistLogStore = existingLogStore || {
				logs: [],
				lastUpdated: new Date().toISOString(),
				maxSize: this.maxLogsPerGist,
				version: "1.0.0",
			};

			// Add new log
			logStore.logs.push(logEvent);
			logStore.lastUpdated = new Date().toISOString();

			// Clean up old logs and rotate if needed
			logStore.logs = this.cleanupLogs(logStore.logs);

			// Update gist
			await this.updateGist(gistId, filename, logStore);
		} catch (error) {
			console.error(
				`Failed to write to GitHub Gist for type ${type}:`,
				error
			);
			// Fallback to console logging
			console.log(
				`[${logEvent.level}] ${logEvent.service}: ${logEvent.message}`
			);
		}
	}

	private async flushLogQueue(): Promise<void> {
		if (this.logQueue.length === 0) return;

		const batch = this.logQueue.splice(0, this.batchSize);
		const logsByType: Record<string, LogEvent[]> = {};

		// Group logs by type
		for (const { type, event } of batch) {
			if (!logsByType[type]) {
				logsByType[type] = [];
			}
			logsByType[type].push(event);
		}

		// Process each type
		const promises = Object.entries(logsByType).map(
			async ([type, events]) => {
				try {
					const gistId = await this.ensureGistExists(type);
					const filename = `${type}-logs.json`;

					// Get existing logs
					const existingLogStore = await this.getGistContent(
						gistId,
						filename
					);

					const logStore: GistLogStore = existingLogStore || {
						logs: [],
						lastUpdated: new Date().toISOString(),
						maxSize: this.maxLogsPerGist,
						version: "1.0.0",
					};

					// Add all new logs
					logStore.logs.push(...events);
					logStore.lastUpdated = new Date().toISOString();

					// Clean up old logs and rotate if needed
					logStore.logs = this.cleanupLogs(logStore.logs);

					// Update gist
					await this.updateGist(gistId, filename, logStore);
				} catch (error) {
					console.error(
						`Failed to batch write to GitHub Gist for type ${type}:`,
						error
					);
					// Log events to console as fallback
					for (const event of events) {
						console.log(
							`[${event.level}] ${event.service}: ${event.message}`
						);
					}
				}
			}
		);

		await Promise.allSettled(promises);
	}

	private async writeLog(type: string, logEvent: LogEvent): Promise<void> {
		try {
			// Add to queue for batching
			this.logQueue.push({ type, event: logEvent });

			// Schedule flush if not already scheduled
			if (!this.flushTimeout) {
				this.flushTimeout = setTimeout(async () => {
					this.flushTimeout = null;
					await this.flushLogQueue();
				}, 5000); // Flush every 5 seconds
			}

			// If queue is full, flush immediately
			if (this.logQueue.length >= this.batchSize) {
				if (this.flushTimeout) {
					clearTimeout(this.flushTimeout);
					this.flushTimeout = null;
				}
				await this.flushLogQueue();
			}

			// Update Prometheus metrics
			if (typeof window === "undefined") {
				// Only on server side
				try {
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

	// Public method to get logs from GitHub Gist
	async getLogsFromGist(type: string = "all"): Promise<LogEvent[]> {
		if (!this.githubToken) {
			return [];
		}

		try {
			if (type === "all") {
				// Get all log types
				const logTypes = ["api", "auth", "chat", "error", "general"];
				const allLogs: LogEvent[] = [];

				const promises = logTypes.map(async (logType) => {
					const gistId = this.gistIds[logType];
					if (!gistId) return [];

					const logStore = await this.getGistContent(
						gistId,
						`${logType}-logs.json`
					);
					return logStore?.logs || [];
				});

				const results = await Promise.allSettled(promises);
				results.forEach((result) => {
					if (result.status === "fulfilled") {
						allLogs.push(...result.value);
					}
				});

				// Sort by timestamp
				return allLogs.sort(
					(a, b) =>
						new Date(b.timestamp).getTime() -
						new Date(a.timestamp).getTime()
				);
			} else {
				const gistId = this.gistIds[type];
				if (!gistId) return [];

				const logStore = await this.getGistContent(
					gistId,
					`${type}-logs.json`
				);
				return logStore?.logs || [];
			}
		} catch (error) {
			console.error("Failed to get logs from GitHub Gist:", error);
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

		// Fire and forget - don't await to avoid blocking
		this.writeLog("api", logEvent).catch(console.error);
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

		// Fire and forget - don't await to avoid blocking
		this.writeLog("auth", logEvent).catch(console.error);
	}

	logChat(event: Partial<ChatLogEvent>): void {
		const logEvent: ChatLogEvent = {
			timestamp: new Date().toISOString(),
			level: "INFO",
			service: "chat",
			message: `Chat interaction`,
			...event,
		};

		// Fire and forget - don't await to avoid blocking
		this.writeLog("chat", logEvent).catch(console.error);
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

		// Fire and forget - don't await to avoid blocking
		this.writeLog("error", logEvent).catch(console.error);
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

		// Fire and forget - don't await to avoid blocking
		this.writeLog("general", logEvent).catch(console.error);
	}

	// Force flush any pending logs (useful for shutdown)
	async flush(): Promise<void> {
		if (this.flushTimeout) {
			clearTimeout(this.flushTimeout);
			this.flushTimeout = null;
		}
		await this.flushLogQueue();
	}

	// Get gist URLs for easy access
	getGistUrls(): Record<string, string> {
		const urls: Record<string, string> = {};
		for (const [type, gistId] of Object.entries(this.gistIds)) {
			if (gistId) {
				urls[type] = `https://gist.github.com/${gistId}`;
			}
		}
		return urls;
	}

	// Get gist size information
	async getGistStats(): Promise<
		Record<string, { count: number; size: string; url: string }>
	> {
		const stats: Record<
			string,
			{ count: number; size: string; url: string }
		> = {};

		for (const [type, gistId] of Object.entries(this.gistIds)) {
			if (gistId) {
				try {
					const logStore = await this.getGistContent(
						gistId,
						`${type}-logs.json`
					);
					const logCount = logStore?.logs.length || 0;
					const sizeBytes = JSON.stringify(logStore).length;
					const sizeKB = (sizeBytes / 1024).toFixed(2);

					stats[type] = {
						count: logCount,
						size: `${sizeKB} KB`,
						url: `https://gist.github.com/${gistId}`,
					};
				} catch {
					stats[type] = {
						count: 0,
						size: "Error",
						url: `https://gist.github.com/${gistId}`,
					};
				}
			}
		}

		return stats;
	}

	// Health check method
	async healthCheck(): Promise<{ healthy: boolean; issues: string[] }> {
		const issues: string[] = [];

		if (!this.githubToken) {
			issues.push("GITHUB_TOKEN not configured");
		}

		// Check if we can access GitHub API
		if (this.githubToken) {
			try {
				const response = await fetch("https://api.github.com/user", {
					headers: {
						Authorization: `Bearer ${this.githubToken}`,
						"User-Agent": "local-llm-logger",
					},
				});

				if (!response.ok) {
					issues.push(
						`GitHub API access failed: ${response.statusText}`
					);
				}
			} catch (error) {
				issues.push(`GitHub API connection failed: ${error}`);
			}
		}

		return {
			healthy: issues.length === 0,
			issues,
		};
	}
}

export const logger = new Logger();
