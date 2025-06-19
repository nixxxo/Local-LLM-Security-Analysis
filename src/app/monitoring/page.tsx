/* eslint-disable @typescript-eslint/no-explicit-any */
"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { useSession } from "next-auth/react";
import Image from "next/image";
import Link from "next/link";
import {
	ArrowLeft,
	Activity,
	Users,
	MessageSquare,
	Shield,
	AlertTriangle,
	Clock,
	TrendingUp,
	Server,
	Eye,
	EyeOff,
	RefreshCw,
	BarChart3,
	Zap,
	Terminal,
	Filter,
	Play,
	Pause,
	Trash2,
	Download,
	Search,
	ArrowDown,
} from "lucide-react";

interface SystemMetrics {
	api: {
		totalRequests: number;
		requestsByEndpoint: Record<string, number>;
		requestsByMethod: Record<string, number>;
		statusCodes: Record<string, number>;
		averageResponseTime: number;
		errorRate: number;
		requestsByHour: Record<string, number>;
		uniqueUsers: number;
		authenticatedRequests: number;
	};
	auth: {
		totalLogins: number;
		loginsByProvider: Record<string, number>;
		failedLogins: number;
		uniqueUsers: string[];
		loginsByHour: Record<string, number>;
		averageSessionsPerUser: number;
	};
	chat: {
		totalChats: number;
		chatsByModel: Record<string, number>;
		averageTokensPerChat: number;
		totalTokens: number;
		chatsByHour: Record<string, number>;
		uniqueChatUsers: number;
		averageResponseTime: number;
	};
	timeRange: {
		start: string;
		end: string;
	};
}

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

// Metric Card Component
const MetricCard = ({
	title,
	value,
	subtitle,
	icon: Icon,
	trend,
	color = "blue",
	className = "",
}: {
	title: string;
	value: string | number;
	subtitle?: string;
	icon: any;
	trend?: "up" | "down" | "neutral";
	color?: "blue" | "green" | "red" | "purple" | "amber";
	className?: string;
}) => {
	const colorClasses = {
		blue: "text-blue-500 bg-blue-500/10 border-blue-500/20",
		green: "text-green-500 bg-green-500/10 border-green-500/20",
		red: "text-red-500 bg-red-500/10 border-red-500/20",
		purple: "text-purple-500 bg-purple-500/10 border-purple-500/20",
		amber: "text-amber-500 bg-amber-500/10 border-amber-500/20",
	};

	const trendIcons = {
		up: <TrendingUp className="w-4 h-4 text-green-500" />,
		down: <TrendingUp className="w-4 h-4 text-red-500 rotate-180" />,
		neutral: <Activity className="w-4 h-4 text-gray-500" />,
	};

	return (
		<div
			className={`glass-morphism p-6 border border-[var(--border-color)] ${className}`}
		>
			<div className="flex items-center justify-between mb-4">
				<div className={`p-3 rounded-xl ${colorClasses[color]} border`}>
					<Icon className="w-6 h-6" />
				</div>
				{trend && trendIcons[trend]}
			</div>
			<div className="space-y-1">
				<h3 className="text-sm font-medium text-[var(--foreground)] opacity-70">
					{title}
				</h3>
				<p className="text-2xl font-bold text-[var(--foreground)]">
					{typeof value === "number" && value > 1000
						? value.toLocaleString()
						: value}
				</p>
				{subtitle && (
					<p className="text-xs text-[var(--foreground)] opacity-50">
						{subtitle}
					</p>
				)}
			</div>
		</div>
	);
};

// Chart Component for simple bar charts
const SimpleBarChart = ({
	data,
	title,
	maxItems = 5,
}: {
	data: Record<string, number>;
	title: string;
	maxItems?: number;
}) => {
	const sortedData = Object.entries(data)
		.sort(([, a], [, b]) => b - a)
		.slice(0, maxItems);

	const maxValue = Math.max(...sortedData.map(([, value]) => value));

	return (
		<div className="glass-morphism p-6 border border-[var(--border-color)]">
			<h3 className="text-lg font-semibold mb-4 text-[var(--foreground)]">
				{title}
			</h3>
			<div className="space-y-3">
				{sortedData.map(([key, value]) => (
					<div key={key} className="space-y-1">
						<div className="flex justify-between text-sm">
							<span className="text-[var(--foreground)] opacity-70 truncate">
								{key}
							</span>
							<span className="font-medium text-[var(--foreground)]">
								{value}
							</span>
						</div>
						<div className="w-full bg-[var(--card-bg)] rounded-full h-2">
							<div
								className="gradient-bg h-2 rounded-full transition-all duration-300"
								style={{
									width: `${(value / maxValue) * 100}%`,
								}}
							/>
						</div>
					</div>
				))}
			</div>
		</div>
	);
};

// Log Entry Component
const LogEntryComponent = ({ log }: { log: LogEntry }) => {
	const getLogLevelColor = (level: string) => {
		switch (level.toLowerCase()) {
			case "error":
				return "text-red-500 bg-red-500/10";
			case "warn":
				return "text-amber-500 bg-amber-500/10";
			case "info":
				return "text-blue-500 bg-blue-500/10";
			case "debug":
				return "text-gray-500 bg-gray-500/10";
			default:
				return "text-[var(--foreground)] bg-[var(--card-bg)]";
		}
	};

	const getSecurityEventColor = (severity?: string) => {
		switch (severity?.toLowerCase()) {
			case "critical":
				return "text-red-600 bg-red-600/20 border-red-600/30";
			case "high":
				return "text-red-500 bg-red-500/15 border-red-500/25";
			case "medium":
				return "text-amber-500 bg-amber-500/15 border-amber-500/25";
			case "low":
				return "text-blue-500 bg-blue-500/15 border-blue-500/25";
			default:
				return "text-gray-500 bg-gray-500/15 border-gray-500/25";
		}
	};

	const getTypeIcon = (type: string) => {
		switch (type.toLowerCase()) {
			case "api":
				return <Server className="w-4 h-4" />;
			case "auth":
				return <Shield className="w-4 h-4" />;
			case "chat":
				return <MessageSquare className="w-4 h-4" />;
			default:
				return <Activity className="w-4 h-4" />;
		}
	};

	const formatTimestamp = (timestamp: string) => {
		return new Date(timestamp).toLocaleTimeString();
	};

	// Check for security events
	const isSecurityEvent = log.metadata?.securityEvent;
	const severity = log.metadata?.severity;
	const riskScore = log.metadata?.riskScore;
	const category = log.metadata?.category;
	const detectedTypes = log.metadata?.detectedTypes;
	const detectedPatterns = log.metadata?.detectedPatterns;
	const filterReason = log.metadata?.filterReason;
	const isContentFiltered = log.metadata?.contentFiltered;

	return (
		<div
			className={`border-b border-[var(--border-color)] last:border-b-0 p-3 hover:bg-[var(--card-bg)]/30 transition-colors ${
				isSecurityEvent &&
				severity &&
				["HIGH", "CRITICAL"].includes(severity)
					? "bg-red-500/5 border-l-4 border-l-red-500"
					: ""
			}`}
		>
			<div className="flex items-start gap-3">
				<div className="flex items-center gap-2 min-w-0 flex-1">
					<div
						className={`p-1 rounded ${getLogLevelColor(log.level)}`}
					>
						{getTypeIcon(log.type)}
					</div>
					<div className="min-w-0 flex-1">
						<div className="flex items-center gap-2 mb-1 flex-wrap">
							<span
								className={`text-xs px-2 py-1 rounded-full font-medium ${getLogLevelColor(
									log.level
								)}`}
							>
								{log.level.toUpperCase()}
							</span>
							<span className="text-xs text-[var(--foreground)] opacity-50">
								{formatTimestamp(log.timestamp)}
							</span>
							{log.endpoint && (
								<span className="text-xs bg-[var(--card-bg)] px-2 py-1 rounded text-[var(--foreground)] opacity-70">
									{log.method} {log.endpoint}
								</span>
							)}
							{log.statusCode && (
								<span
									className={`text-xs px-2 py-1 rounded font-medium ${
										log.statusCode >= 400
											? "text-red-500 bg-red-500/10"
											: log.statusCode >= 300
											? "text-amber-500 bg-amber-500/10"
											: "text-green-500 bg-green-500/10"
									}`}
								>
									{log.statusCode}
								</span>
							)}
							{isSecurityEvent && severity && (
								<span
									className={`text-xs px-2 py-1 rounded-full font-bold border ${getSecurityEventColor(
										severity
									)}`}
								>
									🚨 {severity} SECURITY
								</span>
							)}
						</div>
						<p className="text-sm text-[var(--foreground)] break-words">
							{log.message}
						</p>

						{/* Filter Reason - Show prominently for filtered content */}
						{isContentFiltered && filterReason && (
							<div className="mt-2 p-2 bg-amber-500/10 border border-amber-500/30 rounded">
								<div className="text-xs font-semibold text-amber-600 mb-1">
									🛡️ Content Filtered
								</div>
								<div className="text-xs text-[var(--foreground)] opacity-80">
									<strong>Reason:</strong> {filterReason}
								</div>
							</div>
						)}

						{/* Security Event Details */}
						{isSecurityEvent && (
							<div className="mt-2 p-2 bg-[var(--card-bg)]/50 rounded border">
								<div className="text-xs text-[var(--foreground)] opacity-70 mb-1">
									<strong>Security Event:</strong>{" "}
									{isSecurityEvent}
								</div>
								{category && (
									<div className="text-xs text-[var(--foreground)] opacity-70 mb-1">
										<strong>Category:</strong> {category}
									</div>
								)}
								{riskScore && (
									<div className="text-xs text-[var(--foreground)] opacity-70 mb-1">
										<strong>Risk Score:</strong> {riskScore}
									</div>
								)}
								{detectedTypes &&
									Array.isArray(detectedTypes) &&
									detectedTypes.length > 0 && (
										<div className="text-xs text-[var(--foreground)] opacity-70 mb-1">
											<strong>Detected Types:</strong>{" "}
											{detectedTypes.join(", ")}
										</div>
									)}
								{detectedPatterns &&
									Array.isArray(detectedPatterns) &&
									detectedPatterns.length > 0 && (
										<div className="text-xs text-[var(--foreground)] opacity-70 mb-1">
											<strong>Patterns:</strong>{" "}
											{detectedPatterns
												.slice(0, 3)
												.join(", ")}
											{detectedPatterns.length > 3 &&
												` (+${
													detectedPatterns.length - 3
												} more)`}
										</div>
									)}
								{/* Show filter reason in security details if not already shown above */}
								{!isContentFiltered && filterReason && (
									<div className="text-xs text-[var(--foreground)] opacity-70">
										<strong>Filter Reason:</strong>{" "}
										{filterReason}
									</div>
								)}
							</div>
						)}

						{(log.userEmail || log.ip || log.responseTime) && (
							<div className="flex items-center gap-4 mt-2 text-xs text-[var(--foreground)] opacity-50">
								{log.userEmail && (
									<span>User: {log.userEmail}</span>
								)}
								{log.ip && <span>IP: {log.ip}</span>}
								{log.responseTime && (
									<span>Time: {log.responseTime}ms</span>
								)}
							</div>
						)}
					</div>
				</div>
			</div>
		</div>
	);
};

export default function MonitoringDashboard() {
	const { status } = useSession();
	const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
	const [loading, setLoading] = useState(true);
	const [error, setError] = useState<string | null>(null);
	const [days, setDays] = useState(7);
	const [realtime, setRealtime] = useState(false);
	const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

	// Live logs state
	const [logs, setLogs] = useState<LogEntry[]>([]);
	const [logsLoading, setLogsLoading] = useState(false);
	const [liveLogs, setLiveLogs] = useState(true);
	const [logFilter, setLogFilter] = useState("all");
	const [logSearch, setLogSearch] = useState("");
	const [maxLogs, setMaxLogs] = useState(100);
	const [autoScroll, setAutoScroll] = useState(true);
	const [isAtBottom, setIsAtBottom] = useState(true);
	const logsContainerRef = useRef<HTMLDivElement>(null);

	const fetchMetrics = useCallback(async () => {
		try {
			setLoading(true);
			const params = new URLSearchParams({
				days: days.toString(),
				realtime: realtime.toString(),
			});

			const response = await fetch(`/api/metrics?${params}`);
			if (!response.ok) {
				throw new Error(
					`HTTP ${response.status}: ${response.statusText}`
				);
			}

			const result = await response.json();
			setMetrics(result.data);
			setError(null);
			setLastUpdated(new Date());
		} catch (err) {
			setError(
				err instanceof Error ? err.message : "Failed to fetch metrics"
			);
		} finally {
			setLoading(false);
		}
	}, [days, realtime]);

	const fetchLogs = useCallback(async () => {
		try {
			setLogsLoading(true);
			const response = await fetch(`/api/logs?limit=${maxLogs}`);
			if (!response.ok) {
				throw new Error("Failed to fetch logs");
			}
			const result = await response.json();
			// Fix: Use result.data.logs instead of result.logs
			setLogs(result.data?.logs || []);
		} catch (err) {
			console.error("Failed to fetch logs:", err);
		} finally {
			setLogsLoading(false);
		}
	}, [maxLogs]);

	// Auto-scroll logs to bottom
	useEffect(() => {
		if (logsContainerRef.current && autoScroll && isAtBottom) {
			logsContainerRef.current.scrollTop =
				logsContainerRef.current.scrollHeight;
		}
	}, [logs, autoScroll, isAtBottom]);

	// Check if user is at bottom of logs
	const handleScroll = () => {
		if (logsContainerRef.current) {
			const { scrollTop, scrollHeight, clientHeight } =
				logsContainerRef.current;
			const atBottom = scrollTop + clientHeight >= scrollHeight - 10; // 10px tolerance
			setIsAtBottom(atBottom);
		}
	};

	// Scroll to bottom function
	const scrollToBottom = () => {
		if (logsContainerRef.current) {
			logsContainerRef.current.scrollTop =
				logsContainerRef.current.scrollHeight;
			setIsAtBottom(true);
		}
	};

	// Filter logs based on search and filter
	const filteredLogs = logs.filter((log) => {
		const matchesFilter =
			logFilter === "all" ||
			log.type.toLowerCase() === logFilter ||
			(logFilter === "security" && log.metadata?.securityEvent);
		const matchesSearch =
			logSearch === "" ||
			log.message.toLowerCase().includes(logSearch.toLowerCase()) ||
			log.endpoint?.toLowerCase().includes(logSearch.toLowerCase()) ||
			log.userEmail?.toLowerCase().includes(logSearch.toLowerCase()) ||
			log.metadata?.securityEvent
				?.toLowerCase()
				.includes(logSearch.toLowerCase()) ||
			log.metadata?.category
				?.toLowerCase()
				.includes(logSearch.toLowerCase()) ||
			log.metadata?.filterReason
				?.toLowerCase()
				.includes(logSearch.toLowerCase());
		return matchesFilter && matchesSearch;
	});

	const clearLogs = () => {
		setLogs([]);
	};

	const exportLogs = () => {
		const dataStr = JSON.stringify(filteredLogs, null, 2);
		const dataBlob = new Blob([dataStr], { type: "application/json" });
		const url = URL.createObjectURL(dataBlob);
		const link = document.createElement("a");
		link.href = url;
		link.download = `logs-${new Date().toISOString().split("T")[0]}.json`;
		link.click();
		URL.revokeObjectURL(url);
	};

	useEffect(() => {
		if (status === "authenticated") {
			fetchMetrics();
			fetchLogs();
		}
	}, [status, fetchMetrics, fetchLogs]);

	useEffect(() => {
		if (realtime && status === "authenticated") {
			const interval = setInterval(fetchMetrics, 30000);
			return () => clearInterval(interval);
		}
	}, [realtime, status, fetchMetrics]);

	useEffect(() => {
		if (liveLogs && status === "authenticated") {
			const interval = setInterval(fetchLogs, 5000); // Fetch logs every 5 seconds
			return () => clearInterval(interval);
		}
	}, [liveLogs, status, fetchLogs]);

	if (status === "loading") {
		return (
			<div className="min-h-screen bg-[var(--background)] flex items-center justify-center">
				<div className="glass-morphism p-8">
					<div className="flex items-center gap-3">
						<RefreshCw className="w-6 h-6 animate-spin text-[var(--accent-color)]" />
						<p className="text-[var(--foreground)]">Loading...</p>
					</div>
				</div>
			</div>
		);
	}

	if (status === "unauthenticated") {
		return (
			<div className="min-h-screen bg-[var(--background)] flex items-center justify-center p-4">
				<div className="glass-morphism p-8 text-center max-w-md w-full">
					<Shield className="w-16 h-16 mx-auto mb-4 text-[var(--accent-color)]" />
					<h1 className="text-2xl font-bold mb-4 gradient-text">
						Access Denied
					</h1>
					<p className="text-[var(--foreground)] opacity-70 mb-6">
						Please sign in to view the monitoring dashboard.
					</p>
					<Link
						href="/auth"
						className="gradient-bg text-white px-6 py-3 rounded-full font-medium transition-all hover:opacity-90 inline-block"
					>
						Sign In
					</Link>
				</div>
			</div>
		);
	}

	return (
		<div className="min-h-screen bg-[var(--background)]">
			<div className="max-w-7xl mx-auto">
				{/* Header */}
				<header className="p-6 border-b border-[var(--border-color)]">
					<div className="flex items-center justify-between">
						<div className="flex items-center gap-4">
							<Link
								href="/"
								className="flex items-center text-[var(--accent-color)] hover:opacity-80 transition-opacity"
							>
								<ArrowLeft className="w-5 h-5 mr-2" />
								Back to Home
							</Link>
							<div className="flex items-center gap-3">
								<Image
									src="/logo.png"
									alt="Secured LLM"
									width={40}
									height={40}
									className="rounded-logo"
									priority
								/>
								<h1 className="text-3xl font-bold gradient-text">
									System Monitoring
								</h1>
							</div>
						</div>

						<div className="flex items-center gap-4">
							{/* Time Range Selector */}
							<div className="flex items-center gap-2">
								<Clock className="w-4 h-4 text-[var(--foreground)] opacity-50" />
								<select
									value={days}
									onChange={(e) =>
										setDays(Number(e.target.value))
									}
									className="bg-[var(--card-bg)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--foreground)]"
								>
									<option value={1}>Last 24 hours</option>
									<option value={7}>Last 7 days</option>
									<option value={30}>Last 30 days</option>
								</select>
							</div>

							{/* Real-time Toggle */}
							<button
								onClick={() => setRealtime(!realtime)}
								className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
									realtime
										? "bg-[var(--accent-color)] text-white"
										: "bg-[var(--card-bg)] text-[var(--foreground)] border border-[var(--border-color)]"
								}`}
							>
								{realtime ? (
									<Eye className="w-4 h-4" />
								) : (
									<EyeOff className="w-4 h-4" />
								)}
								Real-time
							</button>

							{/* Refresh Button */}
							<button
								onClick={fetchMetrics}
								disabled={loading}
								className="flex items-center gap-2 gradient-bg text-white px-4 py-2 rounded-lg font-medium hover:opacity-90 transition-opacity disabled:opacity-50"
							>
								<RefreshCw
									className={`w-4 h-4 ${
										loading ? "animate-spin" : ""
									}`}
								/>
								Refresh
							</button>
						</div>
					</div>

					{/* Status Bar */}
					<div className="mt-4 flex items-center justify-between">
						<div className="flex items-center gap-4">
							{realtime && (
								<div className="flex items-center gap-2 text-sm text-green-500">
									<div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
									Live Updates Active
								</div>
							)}
							{lastUpdated && (
								<div className="text-sm text-[var(--foreground)] opacity-50">
									Last updated:{" "}
									{lastUpdated.toLocaleTimeString()}
								</div>
							)}
						</div>

						{error && (
							<div className="flex items-center gap-2 text-sm text-red-500">
								<AlertTriangle className="w-4 h-4" />
								{error}
							</div>
						)}
					</div>
				</header>

				{/* Main Content */}
				<main className="p-6">
					{loading && !metrics ? (
						<div className="flex items-center justify-center py-20">
							<div className="glass-morphism p-8">
								<div className="flex items-center gap-3">
									<RefreshCw className="w-6 h-6 animate-spin text-[var(--accent-color)]" />
									<p className="text-[var(--foreground)]">
										Loading metrics...
									</p>
								</div>
							</div>
						</div>
					) : metrics ? (
						<div className="space-y-8">
							{/* Overview Cards */}
							<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
								<MetricCard
									title="Total API Requests"
									value={metrics.api.totalRequests}
									subtitle="All endpoints"
									icon={Server}
									color="blue"
									trend="up"
								/>
								<MetricCard
									title="Active Users"
									value={metrics.api.uniqueUsers}
									subtitle="Unique users"
									icon={Users}
									color="green"
									trend="up"
								/>
								<MetricCard
									title="Chat Messages"
									value={metrics.chat.totalChats}
									subtitle="Total conversations"
									icon={MessageSquare}
									color="purple"
									trend="up"
								/>
								<MetricCard
									title="Error Rate"
									value={`${metrics.api.errorRate.toFixed(
										1
									)}%`}
									subtitle="Failed requests"
									icon={AlertTriangle}
									color={
										metrics.api.errorRate > 5
											? "red"
											: metrics.api.errorRate > 2
											? "amber"
											: "green"
									}
									trend={
										metrics.api.errorRate > 5
											? "up"
											: "neutral"
									}
								/>
							</div>

							{/* Security Metrics */}
							<div className="mt-8">
								<h3 className="text-xl font-bold mb-4 text-[var(--foreground)] flex items-center gap-2">
									<Shield className="w-6 h-6 text-[var(--accent-color)]" />
									Security Overview
								</h3>
								<div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6">
									<MetricCard
										title="Security Events"
										value={
											filteredLogs.filter(
												(log) =>
													log.metadata?.securityEvent
											).length
										}
										subtitle="Total security events"
										icon={Shield}
										color="red"
										trend="neutral"
									/>
									<MetricCard
										title="Content Filtered"
										value={
											filteredLogs.filter(
												(log) =>
													log.metadata
														?.contentFiltered
											).length
										}
										subtitle="Filtered responses"
										icon={Filter}
										color="amber"
										trend="neutral"
									/>
									<MetricCard
										title="Malicious Attempts"
										value={
											filteredLogs.filter(
												(log) =>
													log.metadata
														?.securityEvent ===
													"MALICIOUS_INTENT_DETECTED"
											).length
										}
										subtitle="Blocked malicious requests"
										icon={AlertTriangle}
										color="red"
										trend="neutral"
									/>
									<MetricCard
										title="PII Detections"
										value={
											filteredLogs.filter(
												(log) =>
													log.metadata
														?.securityEvent ===
													"SENSITIVE_DATA_DETECTED"
											).length
										}
										subtitle="Sensitive data blocked"
										icon={Eye}
										color="purple"
										trend="neutral"
									/>
									<MetricCard
										title="Rate Limit Hits"
										value={
											filteredLogs.filter(
												(log) =>
													log.metadata
														?.securityEvent ===
													"RATE_LIMIT_EXCEEDED"
											).length
										}
										subtitle="Rate limit violations"
										icon={Zap}
										color="blue"
										trend="neutral"
									/>
								</div>
							</div>

							{/* Performance Metrics */}
							<div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
								<MetricCard
									title="Avg Response Time"
									value={`${metrics.api.averageResponseTime.toFixed(
										0
									)}ms`}
									subtitle="API performance"
									icon={Zap}
									color={
										metrics.api.averageResponseTime > 1000
											? "red"
											: metrics.api.averageResponseTime >
											  500
											? "amber"
											: "green"
									}
									className="lg:col-span-1"
								/>
								<MetricCard
									title="Chat Response Time"
									value={`${metrics.chat.averageResponseTime.toFixed(
										0
									)}ms`}
									subtitle="LLM performance"
									icon={Activity}
									color={
										metrics.chat.averageResponseTime > 2000
											? "red"
											: metrics.chat.averageResponseTime >
											  1000
											? "amber"
											: "green"
									}
									className="lg:col-span-1"
								/>
								<MetricCard
									title="Authentication Rate"
									value={`${(
										(metrics.api.authenticatedRequests /
											metrics.api.totalRequests) *
										100
									).toFixed(1)}%`}
									subtitle="Secure requests"
									icon={Shield}
									color="blue"
									className="lg:col-span-1"
								/>
							</div>

							{/* Charts Section */}
							<div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
								<SimpleBarChart
									data={metrics.api.requestsByEndpoint}
									title="Top API Endpoints"
									maxItems={6}
								/>
								<SimpleBarChart
									data={metrics.api.statusCodes}
									title="Response Status Codes"
								/>
							</div>

							{/* Authentication & Chat Analytics */}
							<div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
								<div className="glass-morphism p-6 border border-[var(--border-color)]">
									<h3 className="text-lg font-semibold mb-4 text-[var(--foreground)] flex items-center gap-2">
										<Shield className="w-5 h-5 text-[var(--accent-color)]" />
										Authentication Stats
									</h3>
									<div className="space-y-4">
										<div className="flex justify-between">
											<span className="text-[var(--foreground)] opacity-70">
												Total Logins:
											</span>
											<span className="font-semibold text-[var(--foreground)]">
												{metrics.auth.totalLogins}
											</span>
										</div>
										<div className="flex justify-between">
											<span className="text-[var(--foreground)] opacity-70">
												Failed Attempts:
											</span>
											<span
												className={`font-semibold ${
													metrics.auth.failedLogins >
													0
														? "text-red-500"
														: "text-green-500"
												}`}
											>
												{metrics.auth.failedLogins}
											</span>
										</div>
										<div className="flex justify-between">
											<span className="text-[var(--foreground)] opacity-70">
												Unique Users:
											</span>
											<span className="font-semibold text-[var(--foreground)]">
												{
													metrics.auth.uniqueUsers
														.length
												}
											</span>
										</div>
										<div className="flex justify-between">
											<span className="text-[var(--foreground)] opacity-70">
												Avg Sessions/User:
											</span>
											<span className="font-semibold text-[var(--foreground)]">
												{metrics.auth.averageSessionsPerUser.toFixed(
													1
												)}
											</span>
										</div>
									</div>
								</div>

								<div className="glass-morphism p-6 border border-[var(--border-color)]">
									<h3 className="text-lg font-semibold mb-4 text-[var(--foreground)] flex items-center gap-2">
										<MessageSquare className="w-5 h-5 text-[var(--accent-color)]" />
										Chat Analytics
									</h3>
									<div className="space-y-4">
										<div className="flex justify-between">
											<span className="text-[var(--foreground)] opacity-70">
												Total Tokens:
											</span>
											<span className="font-semibold text-[var(--foreground)]">
												{metrics.chat.totalTokens.toLocaleString()}
											</span>
										</div>
										<div className="flex justify-between">
											<span className="text-[var(--foreground)] opacity-70">
												Avg Tokens/Chat:
											</span>
											<span className="font-semibold text-[var(--foreground)]">
												{metrics.chat.averageTokensPerChat.toFixed(
													0
												)}
											</span>
										</div>
										<div className="flex justify-between">
											<span className="text-[var(--foreground)] opacity-70">
												Active Chat Users:
											</span>
											<span className="font-semibold text-[var(--foreground)]">
												{metrics.chat.uniqueChatUsers}
											</span>
										</div>
									</div>
								</div>

								<SimpleBarChart
									data={metrics.chat.chatsByModel}
									title="AI Model Usage"
								/>
							</div>

							{/* Time Range Info */}
							<div className="glass-morphism p-4 border border-[var(--border-color)]">
								<div className="flex items-center justify-between text-sm text-[var(--foreground)] opacity-70">
									<div className="flex items-center gap-2">
										<BarChart3 className="w-4 h-4" />
										<span>
											Data from{" "}
											{new Date(
												metrics.timeRange.start
											).toLocaleDateString()}{" "}
											to{" "}
											{new Date(
												metrics.timeRange.end
											).toLocaleDateString()}
										</span>
									</div>
									{realtime && (
										<span className="text-green-500">
											• Auto-refreshing every 30 seconds
										</span>
									)}
								</div>
							</div>

							{/* Live Logs Section */}
							<div className="glass-morphism border border-[var(--border-color)]">
								<div className="p-6 border-b border-[var(--border-color)]">
									<div className="flex items-center justify-between mb-4">
										<h2 className="text-2xl font-bold text-[var(--foreground)] flex items-center gap-3">
											<Terminal className="w-6 h-6 text-[var(--accent-color)]" />
											Live System Logs
										</h2>
										<div className="flex items-center gap-3">
											<button
												onClick={() =>
													setLiveLogs(!liveLogs)
												}
												className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
													liveLogs
														? "bg-green-500 text-white"
														: "bg-[var(--card-bg)] text-[var(--foreground)] border border-[var(--border-color)]"
												}`}
											>
												{liveLogs ? (
													<Pause className="w-4 h-4" />
												) : (
													<Play className="w-4 h-4" />
												)}
												{liveLogs ? "Pause" : "Resume"}
											</button>
											<button
												onClick={() =>
													setAutoScroll(!autoScroll)
												}
												className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
													autoScroll
														? "bg-blue-500 text-white"
														: "bg-[var(--card-bg)] text-[var(--foreground)] border border-[var(--border-color)]"
												}`}
											>
												<ArrowDown className="w-4 h-4" />
												Auto-scroll
											</button>
											<button
												onClick={clearLogs}
												className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium bg-red-500/10 text-red-500 border border-red-500/20 hover:bg-red-500/20 transition-all"
											>
												<Trash2 className="w-4 h-4" />
												Clear
											</button>
											<button
												onClick={exportLogs}
												className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium bg-[var(--card-bg)] text-[var(--foreground)] border border-[var(--border-color)] hover:bg-[var(--card-bg)]/70 transition-all"
											>
												<Download className="w-4 h-4" />
												Export
											</button>
										</div>
									</div>

									{/* Log Controls */}
									<div className="flex items-center gap-4 mb-4">
										<div className="flex items-center gap-2">
											<Filter className="w-4 h-4 text-[var(--foreground)] opacity-50" />
											<select
												value={logFilter}
												onChange={(e) =>
													setLogFilter(e.target.value)
												}
												className="bg-[var(--card-bg)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--foreground)]"
											>
												<option value="all">
													All Types
												</option>
												<option value="api">API</option>
												<option value="auth">
													Auth
												</option>
												<option value="chat">
													Chat
												</option>
												<option value="security">
													🚨 Security Events
												</option>
											</select>
										</div>

										<div className="flex items-center gap-2 flex-1 max-w-md">
											<Search className="w-4 h-4 text-[var(--foreground)] opacity-50" />
											<input
												type="text"
												placeholder="Search logs..."
												value={logSearch}
												onChange={(e) =>
													setLogSearch(e.target.value)
												}
												className="flex-1 bg-[var(--card-bg)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--foreground)] placeholder-[var(--foreground)]/50"
											/>
										</div>

										<div className="flex items-center gap-2">
											<span className="text-sm text-[var(--foreground)] opacity-70">
												Max:
											</span>
											<select
												value={maxLogs}
												onChange={(e) =>
													setMaxLogs(
														Number(e.target.value)
													)
												}
												className="bg-[var(--card-bg)] border border-[var(--border-color)] rounded-lg px-3 py-2 text-sm text-[var(--foreground)]"
											>
												<option value={50}>50</option>
												<option value={100}>100</option>
												<option value={200}>200</option>
												<option value={500}>500</option>
											</select>
										</div>
									</div>

									{/* Log Stats */}
									<div className="flex items-center gap-6 text-sm text-[var(--foreground)] opacity-70">
										<span>Total: {logs.length}</span>
										<span>
											Filtered: {filteredLogs.length}
										</span>
										{autoScroll && (
											<span className="flex items-center gap-1 text-blue-500">
												<ArrowDown className="w-3 h-3" />
												Auto-scroll
											</span>
										)}
										{liveLogs && (
											<span className="flex items-center gap-1 text-green-500">
												<div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
												Live updates
											</span>
										)}
										{logsLoading && (
											<span className="flex items-center gap-1">
												<RefreshCw className="w-3 h-3 animate-spin" />
												Loading...
											</span>
										)}
									</div>
								</div>

								{/* Logs Container */}
								<div className="relative">
									<div
										ref={logsContainerRef}
										onScroll={handleScroll}
										className="h-96 overflow-y-auto"
									>
										{filteredLogs.length > 0 ? (
											filteredLogs.map((log, index) => (
												<LogEntryComponent
													key={index}
													log={log}
												/>
											))
										) : (
											<div className="flex items-center justify-center h-full text-[var(--foreground)] opacity-50">
												<div className="text-center">
													<Terminal className="w-12 h-12 mx-auto mb-2 opacity-30" />
													<p>No logs found</p>
													{logSearch && (
														<p className="text-xs mt-1">
															Try adjusting your
															search or filter
														</p>
													)}
												</div>
											</div>
										)}
									</div>

									{/* Scroll to Bottom Button */}
									{!isAtBottom && filteredLogs.length > 0 && (
										<button
											onClick={scrollToBottom}
											className="absolute bottom-4 right-4 bg-[var(--accent-color)] text-white p-3 rounded-full shadow-lg hover:opacity-90 transition-all animate-bounce"
											title="Scroll to latest logs"
										>
											<ArrowDown className="w-5 h-5" />
										</button>
									)}
								</div>
							</div>
						</div>
					) : (
						<div className="flex items-center justify-center py-20">
							<div className="glass-morphism p-8 text-center">
								<AlertTriangle className="w-16 h-16 mx-auto mb-4 text-amber-500" />
								<h2 className="text-xl font-semibold mb-2 text-[var(--foreground)]">
									No Data Available
								</h2>
								<p className="text-[var(--foreground)] opacity-70">
									Unable to load monitoring data. Please try
									refreshing.
								</p>
							</div>
						</div>
					)}
				</main>
			</div>
		</div>
	);
}
