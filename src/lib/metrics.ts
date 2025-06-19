import { LogEvent, AuthLogEvent, ChatLogEvent, logger } from "./logger";
import {
	register,
	collectDefaultMetrics,
	Counter,
	Gauge,
	Histogram,
} from "prom-client";

// Initialize Prometheus metrics
collectDefaultMetrics({ register });

// Custom metrics for our application
const httpRequestsTotal = new Counter({
	name: "http_requests_total",
	help: "Total number of HTTP requests",
	labelNames: ["method", "endpoint", "status_code"],
	registers: [register],
});

const httpRequestDuration = new Histogram({
	name: "http_request_duration_seconds",
	help: "Duration of HTTP requests in seconds",
	labelNames: ["method", "endpoint"],
	buckets: [0.1, 0.5, 1, 2, 5],
	registers: [register],
});

const authEventsTotal = new Counter({
	name: "auth_events_total",
	help: "Total number of authentication events",
	labelNames: ["action", "provider"],
	registers: [register],
});

const chatMessagesTotal = new Counter({
	name: "chat_messages_total",
	help: "Total number of chat messages",
	labelNames: ["model"],
	registers: [register],
});

const chatTokensTotal = new Counter({
	name: "chat_tokens_total",
	help: "Total number of tokens used in chat",
	labelNames: ["model", "type"],
	registers: [register],
});

const activeUsers = new Gauge({
	name: "active_users_total",
	help: "Number of active users",
	labelNames: ["timeframe"],
	registers: [register],
});

export interface ApiMetrics {
	totalRequests: number;
	requestsByEndpoint: Record<string, number>;
	requestsByMethod: Record<string, number>;
	statusCodes: Record<string, number>;
	averageResponseTime: number;
	errorRate: number;
	requestsByHour: Record<string, number>;
	uniqueUsers: number;
	authenticatedRequests: number;
}

export interface AuthMetrics {
	totalLogins: number;
	loginsByProvider: Record<string, number>;
	failedLogins: number;
	uniqueUsers: Set<string>;
	loginsByHour: Record<string, number>;
	averageSessionsPerUser: number;
}

export interface ChatMetrics {
	totalChats: number;
	chatsByModel: Record<string, number>;
	averageTokensPerChat: number;
	totalTokens: number;
	chatsByHour: Record<string, number>;
	uniqueChatUsers: number;
	averageResponseTime: number;
}

export interface SystemMetrics {
	api: ApiMetrics;
	auth: AuthMetrics;
	chat: ChatMetrics;
	timeRange: {
		start: string;
		end: string;
	};
}

class MetricsCollector {
	constructor() {
		// No need for file system or Edge Config setup
	}

	private async readLogsFromGist(
		type: string,
		days: number = 7
	): Promise<LogEvent[]> {
		try {
			const logs = await logger.getLogsFromGist(type);

			// Filter logs by date range
			const cutoffDate = new Date();
			cutoffDate.setDate(cutoffDate.getDate() - days);

			return logs.filter((log) => new Date(log.timestamp) >= cutoffDate);
		} catch (error) {
			console.error(
				`Failed to read logs from GitHub Gist for type ${type}:`,
				error
			);
			return [];
		}
	}

	private getHourKey(timestamp: string): string {
		return new Date(timestamp).toISOString().slice(0, 13);
	}

	private calculateApiMetrics(logs: LogEvent[]): ApiMetrics {
		const requestsByEndpoint: Record<string, number> = {};
		const requestsByMethod: Record<string, number> = {};
		const statusCodes: Record<string, number> = {};
		const requestsByHour: Record<string, number> = {};
		const userEmails = new Set<string>();

		let totalResponseTime = 0;
		let responseTimeCount = 0;
		let errorCount = 0;
		let authenticatedCount = 0;

		for (const log of logs) {
			// Count requests by endpoint
			if (log.endpoint) {
				requestsByEndpoint[log.endpoint] =
					(requestsByEndpoint[log.endpoint] || 0) + 1;
			}

			// Count requests by method
			if (log.method) {
				requestsByMethod[log.method] =
					(requestsByMethod[log.method] || 0) + 1;
			}

			// Count status codes
			if (log.statusCode) {
				const statusKey = log.statusCode.toString();
				statusCodes[statusKey] = (statusCodes[statusKey] || 0) + 1;

				if (log.statusCode >= 400) {
					errorCount++;
				}
			}

			// Track response times
			if (log.responseTime) {
				totalResponseTime += log.responseTime;
				responseTimeCount++;
			}

			// Track unique users
			if (log.userEmail) {
				userEmails.add(log.userEmail);
			}

			// Count authenticated requests
			if (log.metadata?.authenticated) {
				authenticatedCount++;
			}

			// Requests by hour
			const hourKey = this.getHourKey(log.timestamp);
			requestsByHour[hourKey] = (requestsByHour[hourKey] || 0) + 1;
		}

		return {
			totalRequests: logs.length,
			requestsByEndpoint,
			requestsByMethod,
			statusCodes,
			averageResponseTime:
				responseTimeCount > 0
					? totalResponseTime / responseTimeCount
					: 0,
			errorRate: logs.length > 0 ? (errorCount / logs.length) * 100 : 0,
			requestsByHour,
			uniqueUsers: userEmails.size,
			authenticatedRequests: authenticatedCount,
		};
	}

	private calculateAuthMetrics(logs: AuthLogEvent[]): AuthMetrics {
		const loginsByProvider: Record<string, number> = {};
		const loginsByHour: Record<string, number> = {};
		const uniqueUsers = new Set<string>();

		let totalLogins = 0;
		let failedLogins = 0;

		for (const log of logs) {
			if (log.action === "LOGIN") {
				totalLogins++;

				if (log.provider) {
					loginsByProvider[log.provider] =
						(loginsByProvider[log.provider] || 0) + 1;
				}

				if (log.userEmail) {
					uniqueUsers.add(log.userEmail);
				}

				const hourKey = this.getHourKey(log.timestamp);
				loginsByHour[hourKey] = (loginsByHour[hourKey] || 0) + 1;
			} else if (log.action === "LOGIN_FAILED") {
				failedLogins++;
			}
		}

		return {
			totalLogins,
			loginsByProvider,
			failedLogins,
			uniqueUsers,
			loginsByHour,
			averageSessionsPerUser:
				uniqueUsers.size > 0 ? totalLogins / uniqueUsers.size : 0,
		};
	}

	private calculateChatMetrics(logs: ChatLogEvent[]): ChatMetrics {
		const chatsByModel: Record<string, number> = {};
		const chatsByHour: Record<string, number> = {};
		const uniqueUsers = new Set<string>();

		let totalTokens = 0;
		let totalResponseTime = 0;
		let responseTimeCount = 0;

		for (const log of logs) {
			if (log.model) {
				chatsByModel[log.model] = (chatsByModel[log.model] || 0) + 1;
			}

			if (log.tokens) {
				totalTokens += log.tokens.total;
			}

			if (log.userEmail) {
				uniqueUsers.add(log.userEmail);
			}

			if (log.responseTime) {
				totalResponseTime += log.responseTime;
				responseTimeCount++;
			}

			const hourKey = this.getHourKey(log.timestamp);
			chatsByHour[hourKey] = (chatsByHour[hourKey] || 0) + 1;
		}

		return {
			totalChats: logs.length,
			chatsByModel,
			averageTokensPerChat:
				logs.length > 0 ? totalTokens / logs.length : 0,
			totalTokens,
			chatsByHour,
			uniqueChatUsers: uniqueUsers.size,
			averageResponseTime:
				responseTimeCount > 0
					? totalResponseTime / responseTimeCount
					: 0,
		};
	}

	async getMetrics(days: number = 7): Promise<SystemMetrics> {
		const [apiLogs, authLogs, chatLogs] = await Promise.all([
			this.readLogsFromGist("api", days),
			this.readLogsFromGist("auth", days),
			this.readLogsFromGist("chat", days),
		]);

		const endDate = new Date();
		const startDate = new Date();
		startDate.setDate(startDate.getDate() - days);

		return {
			api: this.calculateApiMetrics(apiLogs),
			auth: this.calculateAuthMetrics(authLogs as AuthLogEvent[]),
			chat: this.calculateChatMetrics(chatLogs as ChatLogEvent[]),
			timeRange: {
				start: startDate.toISOString(),
				end: endDate.toISOString(),
			},
		};
	}

	// Get real-time metrics for the last hour
	async getRealTimeMetrics(): Promise<SystemMetrics> {
		return await this.getMetrics(1);
	}

	// Get aggregated metrics for Grafana
	async getGrafanaMetrics(
		days: number = 7
	): Promise<Record<string, string | number>> {
		const metrics = await this.getMetrics(days);

		return {
			api_total_requests: metrics.api.totalRequests,
			api_error_rate: metrics.api.errorRate,
			api_avg_response_time: metrics.api.averageResponseTime,
			api_unique_users: metrics.api.uniqueUsers,
			auth_total_logins: metrics.auth.totalLogins,
			auth_failed_logins: metrics.auth.failedLogins,
			auth_unique_users: metrics.auth.uniqueUsers.size,
			chat_total_chats: metrics.chat.totalChats,
			chat_total_tokens: metrics.chat.totalTokens,
			chat_unique_users: metrics.chat.uniqueChatUsers,
			timestamp: new Date().toISOString(),
		};
	}

	// Update Prometheus metrics from log events
	updatePrometheusMetrics(logEvent: LogEvent): void {
		try {
			if (
				logEvent.service === "api" &&
				logEvent.endpoint &&
				logEvent.method
			) {
				httpRequestsTotal
					.labels(
						logEvent.method,
						logEvent.endpoint,
						logEvent.statusCode?.toString() || "unknown"
					)
					.inc();

				if (logEvent.responseTime) {
					httpRequestDuration
						.labels(logEvent.method, logEvent.endpoint)
						.observe(logEvent.responseTime / 1000); // Convert to seconds
				}
			}

			if (logEvent.service === "auth") {
				const authEvent = logEvent as AuthLogEvent;
				authEventsTotal
					.labels(
						authEvent.action || "unknown",
						authEvent.provider || "unknown"
					)
					.inc();
			}

			if (logEvent.service === "chat") {
				const chatEvent = logEvent as ChatLogEvent;
				chatMessagesTotal.labels(chatEvent.model || "unknown").inc();

				if (chatEvent.tokens) {
					chatTokensTotal
						.labels(chatEvent.model || "unknown", "prompt")
						.inc(chatEvent.tokens.prompt);
					chatTokensTotal
						.labels(chatEvent.model || "unknown", "completion")
						.inc(chatEvent.tokens.completion);
				}
			}
		} catch (error) {
			console.warn("Failed to update Prometheus metrics:", error);
		}
	}

	// Get Prometheus metrics string
	async getPrometheusMetrics(): Promise<string> {
		try {
			// Update active users gauge
			const metrics = await this.getMetrics(1); // Last 24 hours
			activeUsers.labels("24h").set(metrics.api.uniqueUsers);
			activeUsers.labels("chat").set(metrics.chat.uniqueChatUsers);

			return await register.metrics();
		} catch (error) {
			console.error("Failed to generate Prometheus metrics:", error);
			return "";
		}
	}
}

export const metricsCollector = new MetricsCollector();
