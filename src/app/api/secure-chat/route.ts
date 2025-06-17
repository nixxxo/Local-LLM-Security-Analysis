/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
import { NextRequest, NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/app/api/auth/[...nextauth]/route";
import { logger } from "@/lib/logger";
import { withLogging } from "@/lib/middleware";

// ===================== TYPES =====================
interface RateLimitEntry {
	count: number;
	timestamp: number;
	consecutiveRequests: number;
	lastRequestTime: number;
}

interface SanitizedParams {
	message: string;
	model: string;
	temperature: number;
	top_p: number;
	max_tokens: number;
	frequency_penalty: number;
	presence_penalty: number;
	stop_sequences: string[] | undefined;
	seed: number | undefined;
}

interface ContentFilterResult {
	filtered: boolean;
	content: string;
}

interface RateLimitResult {
	allowed: boolean;
	remaining: number;
	blacklisted: boolean;
	cooldown: boolean;
}

// ===================== CONSTANTS =====================
// Rate limiting
const MAX_REQUESTS_PER_MINUTE = 15;
const MAX_CONSECUTIVE_REQUESTS = 2;
const SHORT_TIME_WINDOW = 1000; // 1 second
const BLACKLIST_DURATION = 60 * 1000; // 60 seconds

// Input validation
const MAX_INPUT_SIZE = 10000;

// Request management
const MAX_REQUEST_TIMEOUT = 60000;

// In-memory stores (would use Redis in production)
const rateLimitStore = new Map<string, RateLimitEntry>();
const blacklistedIPs = new Set<string>();

// ===================== SECURITY FUNCTIONS =====================

/**
 * Extract client IP from request headers
 * Protection: Accurate IP identification for rate limiting
 */
function extractClientIP(request: NextRequest): string {
	const forwardedFor = request.headers.get("x-forwarded-for");
	const realIp = request.headers.get("x-real-ip");
	return forwardedFor
		? forwardedFor.split(",")[0].trim()
		: realIp || "unknown";
}

/**
 * JSON parsing with error handling
 * Protection: Against malformed JSON attacks
 */
async function safeJsonParse(request: NextRequest): Promise<any> {
	try {
		return await request.json();
	} catch (error) {
		throw new Error("Invalid request format or payload too large");
	}
}

/**
 * Input validation and sanitization
 * Protection: Against malicious input, parameter manipulation, and input size attacks
 */
function validateRequestData(data: any): SanitizedParams {
	// Check if required fields exist
	if (!data.message || typeof data.message !== "string") {
		throw new Error("Message is required and must be a string");
	}

	// Check input size to prevent resource exhaustion
	if (data.message.length > MAX_INPUT_SIZE) {
		throw new Error(
			`Message exceeds maximum allowed size of ${MAX_INPUT_SIZE} characters`
		);
	}

	// Validate and sanitize parameters
	return {
		message: data.message.trim(),
		model: ["gemma3:1b", "mistral"].includes(data.model)
			? data.model
			: "gemma3:1b",
		temperature:
			data.temperature !== undefined
				? Math.min(Math.max(parseFloat(data.temperature), 0), 1)
				: 0.7,
		top_p:
			data.top_p !== undefined
				? Math.min(Math.max(parseFloat(data.top_p), 0), 1)
				: 0.9,
		max_tokens:
			data.max_tokens !== undefined
				? Math.min(Math.max(parseInt(data.max_tokens), 1), 4096)
				: 2048,
		frequency_penalty:
			data.frequency_penalty !== undefined
				? Math.min(Math.max(parseFloat(data.frequency_penalty), 0), 2)
				: 0,
		presence_penalty:
			data.presence_penalty !== undefined
				? Math.min(Math.max(parseFloat(data.presence_penalty), 0), 2)
				: 0,
		stop_sequences: Array.isArray(data.stop_sequences)
			? data.stop_sequences.slice(0, 5)
			: undefined,
		seed: data.seed !== undefined ? parseInt(data.seed) : undefined,
	};
}

/**
 * Content filtering
 * Protection: Against harmful content in requests or responses
 */
function filterHarmfulContent(content: string): ContentFilterResult {
	const harmfulPatterns = [
		/bomb/i,
		/explosive/i,
		/weapon/i,
		/hack/i,
		/exploit/i,
		/understood:/i,
		/illegal/i,
		/harmful/i,
	];

	let filtered = false;
	for (const pattern of harmfulPatterns) {
		if (pattern.test(content)) {
			filtered = true;
			content =
				"I cannot provide information that could be harmful or dangerous. If you have legitimate questions, please rephrase your request.";
			break;
		}
	}

	return { filtered, content };
}

async function scanContentWithNightfall(content: string): Promise<boolean> {
	const apiKey = process.env.NIGHTFALL_API_KEY || "NF-nkIlk4e5rF3UogLL4ZZK9szbxg0IKxLq";
	const url = "https://api.nightfall.ai/v3/scan";

	const payload = {
		policy: {
			detectionRules: [
				{
					detectors: [
						{
							minNumFindings: 1,
							minConfidence: "VERY_LIKELY",
							displayName: "US Social Security Number",
							detectorType: "NIGHTFALL_DETECTOR",
							nightfallDetector: "US_SOCIAL_SECURITY_NUMBER",
						},
						{
							redactionConfig: {
								maskConfig: {
									charsToIgnore: ["-"],
									maskingChar: "X",
									maskRightToLeft: true,
									numCharsToLeaveUnMasked: 4,
								},
							},
							minNumFindings: 1,
							minConfidence: "VERY_LIKELY",
							displayName: "Credit Card Number",
							detectorType: "NIGHTFALL_DETECTOR",
							nightfallDetector: "CREDIT_CARD_NUMBER",
						},
					],
					name: "My Match Rule",
					logicalOp: "ANY",
				},
			],
		},
		payload: [content], // Pass the actual user content here
	};

	const response = await fetch(url, {
		method: "POST",
		headers: {
			"Accept": "application/json",
			"Authorization": `Bearer ${apiKey}`,
			"Content-Type": "application/json",
		},
		body: JSON.stringify(payload),
	});

	if (!response.ok) {
		throw new Error(`Nightfall API responded with status ${response.status}`);
	}

	const data = await response.json();
	console.log("Nightfall scan result:", data);

	// Nightfall returns findings; if any findings, treat as harmful
	return data.findings && data.findings.some(innerArray => innerArray.length > 0);
}



/**
 * Check for IP address in blacklist
 * Protection: Against known malicious actors
 */
function isIPBlacklisted(ip: string): boolean {
	return blacklistedIPs.has(ip);
}

/**
 * Update IP entry in rate limiting system
 * Protection: Against rapid consecutive requests (DoS protection)
 */
function updateRateLimitEntry(ip: string): RateLimitEntry {
	const now = Date.now();

	// Get or create rate limit entry
	let entry = rateLimitStore.get(ip);
	if (!entry) {
		entry = {
			count: 0,
			timestamp: now,
			consecutiveRequests: 0,
			lastRequestTime: now,
		};
		rateLimitStore.set(ip, entry);
	}

	// Update entry with new request data
	const timeSinceLastRequest = now - entry.lastRequestTime;

	if (timeSinceLastRequest < SHORT_TIME_WINDOW) {
		entry.consecutiveRequests += 1;
		console.log(
			`IP ${ip} consecutive requests: ${entry.consecutiveRequests}`
		);
	} else {
		// Only reset consecutive counter if significant time has passed
		if (timeSinceLastRequest > 5000) {
			// 5 seconds
			entry.consecutiveRequests = 1;
		} else {
			// Still count as part of a potential attack pattern but with less weight
			entry.consecutiveRequests = Math.max(
				1,
				entry.consecutiveRequests - 1
			);
		}
	}

	// Update timestamps and counter
	entry.lastRequestTime = now;
	entry.count += 1;
	entry.timestamp = now;

	return entry;
}

/**
 * Check if IP should be blacklisted based on behavior
 * Protection: Against DoS attacks
 */
function checkAndBlacklistIP(ip: string, entry: RateLimitEntry): boolean {
	if (entry.consecutiveRequests >= MAX_CONSECUTIVE_REQUESTS) {
		console.log(
			`Blacklisting IP: ${ip} - ${entry.consecutiveRequests} consecutive requests`
		);
		blacklistedIPs.add(ip);
		return true;
	}
	return false;
}

/**
 * Apply rate limiting based on IP address
 * Protection: Against DoS and brute-force attacks
 */
function checkRateLimit(ip: string): RateLimitResult {
	// Check if IP is already blacklisted
	if (isIPBlacklisted(ip)) {
		console.log(`Blocked blacklisted IP: ${ip}`);
		return {
			allowed: false,
			remaining: 0,
			blacklisted: true,
			cooldown: false,
		};
	}

	// Update rate limit entry for this IP
	const entry = updateRateLimitEntry(ip);

	// Check if IP should be blacklisted based on behavior
	if (checkAndBlacklistIP(ip, entry)) {
		return {
			allowed: false,
			remaining: 0,
			blacklisted: true,
			cooldown: false,
		};
	}

	// Check if over the minute limit but not blacklisted yet
	if (entry.count > MAX_REQUESTS_PER_MINUTE) {
		console.log(`Rate limited IP: ${ip} - ${entry.count} requests`);
		return {
			allowed: false,
			remaining: 0,
			blacklisted: false,
			cooldown: true,
		};
	}

	// All checks passed
	return {
		allowed: true,
		remaining: Math.max(0, MAX_REQUESTS_PER_MINUTE - entry.count),
		blacklisted: false,
		cooldown: false,
	};
}

/**
 * Generate rate limit headers for responses
 * Protection: Follows best practices for rate-limited APIs
 */
function getRateLimitHeaders(remaining: number): HeadersInit {
	return {
		"X-RateLimit-Limit": MAX_REQUESTS_PER_MINUTE.toString(),
		"X-RateLimit-Remaining": remaining.toString(),
		"X-RateLimit-Reset": (Math.floor(Date.now() / 60000) + 1).toString(),
	};
}

/**
 * Create error response for rate limiting and blacklisting
 * Protection: Provides appropriate error responses without exposing system details
 */
function createRateLimitResponse(rateLimit: RateLimitResult): NextResponse {
	if (rateLimit.blacklisted) {
		return NextResponse.json(
			{
				error: "Access temporarily restricted due to aggressive request patterns. Please try again later.",
				retryAfter: 60,
			},
			{
				status: 429,
				headers: {
					...getRateLimitHeaders(0),
					"Retry-After": "60",
				},
			}
		);
	} else if (rateLimit.cooldown) {
		return NextResponse.json(
			{
				error: "Rate limit exceeded. Please try again later.",
				retryAfter: 60,
				remaining: 0,
			},
			{
				status: 429,
				headers: {
					...getRateLimitHeaders(0),
					"Retry-After": "60",
				},
			}
		);
	}

	// This should never happen as this function should only be called when rate limited
	return NextResponse.json(
		{ error: "Rate limit error" },
		{ status: 429, headers: getRateLimitHeaders(0) }
	);
}

/**
 * Timeout-protected fetch to external API
 * Protection: Against hanging connections and resource exhaustion
 */
async function timeoutProtectedFetch(requestParams: any): Promise<any> {
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), MAX_REQUEST_TIMEOUT);

	try {
		const response = await fetch(process.env.OLLAMA_URL || "", {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
			},
			body: JSON.stringify(requestParams),
			signal: controller.signal,
		});

		clearTimeout(timeoutId);

		if (!response.ok) {
			throw new Error(`API responded with status ${response.status}`);
		}

		return await response.json();
	} catch (error) {
		clearTimeout(timeoutId);

		if (error instanceof DOMException && error.name === "AbortError") {
			throw new Error("Request timed out");
		}

		throw error;
	}
}

// ===================== MAINTENANCE ROUTINE =====================

/**
 * Cleanup routine for rate limiting and blacklist data
 * Protection: Prevents memory leaks and ensures fair service restoration
 */
setInterval(() => {
	const now = Date.now();

	// Reset counters for rate limiting when their minute has passed
	for (const [ip, entry] of rateLimitStore.entries()) {
		if (now - entry.timestamp > 60 * 1000) {
			entry.count = 0;
			entry.timestamp = now;
		}
	}

	// Clear blacklisted IPs after blacklist duration
	for (const ip of blacklistedIPs) {
		const entry = rateLimitStore.get(ip);
		if (entry && now - entry.timestamp > BLACKLIST_DURATION) {
			blacklistedIPs.delete(ip);
			console.log(`Removing ${ip} from blacklist`);
		}
	}
}, 60 * 1000);

// ===================== MAIN ROUTE HANDLER =====================

async function secureChatHandler(request: NextRequest): Promise<NextResponse> {
	const startTime = Date.now();
	let session;

	try {
		// Authentication check
		session = await getServerSession(authOptions);
		if (!session?.user?.email) {
			logger.logAuth({
				action: "LOGIN_FAILED",
				endpoint: "/api/secure-chat",
				ip: extractClientIP(request),
				userAgent: request.headers.get("user-agent") || "unknown",
				message: "Unauthorized access attempt to secure chat",
			});

			return NextResponse.json(
				{ error: "Authentication required" },
				{ status: 401 }
			);
		}

		const ip = extractClientIP(request);

		// Check if IP is blacklisted
		if (isIPBlacklisted(ip)) {
			logger.logApi({
				endpoint: "/api/secure-chat",
				method: "POST",
				userId: session.user.email,
				ip,
				statusCode: 429,
				message: "Request from blacklisted IP",
				metadata: { blacklisted: true },
			});

			return NextResponse.json(
				{ error: "Access denied", reason: "IP temporarily blocked" },
				{ status: 429 }
			);
		}

		// Rate limiting check
		const rateLimit = checkRateLimit(ip);
		if (!rateLimit.allowed) {
			logger.logApi({
				endpoint: "/api/secure-chat",
				method: "POST",
				userId: session.user.email,
				ip,
				statusCode: 429,
				message: "Rate limit exceeded",
				metadata: {
					rateLimit: {
						remaining: rateLimit.remaining,
						blacklisted: rateLimit.blacklisted,
						cooldown: rateLimit.cooldown,
					},
				},
			});

			return createRateLimitResponse(rateLimit);
		}

		// Parse and validate request data
		const requestData = await safeJsonParse(request);
		const validatedParams = validateRequestData(requestData);
		const hasHarmfulPII = await scanContentWithNightfall(validatedParams.message);
		console.log("Nightfall PII scan result:", hasHarmfulPII);
		if (hasHarmfulPII) {
			logger.logApi({
				endpoint: "/api/secure-chat",
				method: "POST",
				userId: session.user.email,
				ip: extractClientIP(request),
				statusCode: 400,
				message: "PII or sensitive content detected by Nightfall",
				metadata: { contentFiltered: true },
			});

			return NextResponse.json(
				{
					error: "Content blocked due to sensitive information detected.",
					message:
						"I cannot provide information that could be harmful or dangerous. If you have legitimate questions, please rephrase your request.",
				},
				{ status: 400 }
			);
		}



		// Check for harmful content in user input
		const contentFilter = filterHarmfulContent(validatedParams.message);
		if (contentFilter.filtered) {
			logger.logApi({
				endpoint: "/api/secure-chat",
				method: "POST",
				userId: session.user.email,
				ip,
				statusCode: 400,
				message: "Harmful content detected and blocked",
				metadata: {
					contentFiltered: true,
					originalMessageLength: validatedParams.message.length,
				},
			});

			return NextResponse.json(
				{
					error: "Content blocked",
					message: contentFilter.content,
				},
				{ status: 400 }
			);
		}

		// Prepare request for Ollama
		const messages = [
			{
				role: "system",
				content:
					"You are a helpful and safe AI assistant. Provide accurate, helpful responses while avoiding harmful, illegal, or inappropriate content.",
			},
			{ role: "user", content: validatedParams.message },
		];

		const requestParams = {
			model: validatedParams.model,
			messages: messages,
			stream: false,
			temperature: validatedParams.temperature,
			top_p: validatedParams.top_p,
			max_tokens: validatedParams.max_tokens,
			frequency_penalty: validatedParams.frequency_penalty,
			presence_penalty: validatedParams.presence_penalty,
			stop: validatedParams.stop_sequences,
			seed: validatedParams.seed,
		};

		// Make request to Ollama with timeout protection
		const data = await timeoutProtectedFetch(requestParams);
		const responseTime = Date.now() - startTime;

		// Filter response content
		const responseFilter = filterHarmfulContent(
			data.message?.content || ""
		);

		// Log successful chat interaction
		logger.logChat({
			endpoint: "/api/secure-chat",
			method: "POST",
			userId: session.user.email,
			userEmail: session.user.email,
			ip,
			model: validatedParams.model,
			temperature: validatedParams.temperature,
			responseTime,
			tokens: {
				prompt: data.prompt_eval_count || 0,
				completion: data.eval_count || 0,
				total: (data.prompt_eval_count || 0) + (data.eval_count || 0),
			},
			metadata: {
				messageLength: validatedParams.message.length,
				secure: true,
				contentFiltered: responseFilter.filtered,
				parameters: {
					temperature: validatedParams.temperature,
					top_p: validatedParams.top_p,
					max_tokens: validatedParams.max_tokens,
					frequency_penalty: validatedParams.frequency_penalty,
					presence_penalty: validatedParams.presence_penalty,
					model: validatedParams.model,
				},
			},
		});

		return NextResponse.json(
			{
				message: {
					role: "assistant",
					content: responseFilter.content,
				},
				done: true,
				model: validatedParams.model,
				prompt_tokens: data.prompt_eval_count,
				completion_tokens: data.eval_count,
				total_tokens:
					(data.prompt_eval_count || 0) + (data.eval_count || 0),
				filtered: responseFilter.filtered,
			},
			{
				headers: getRateLimitHeaders(rateLimit.remaining),
			}
		);
	} catch (error) {
		const responseTime = Date.now() - startTime;

		logger.logError("secure-chat", error as Error, {
			endpoint: "/api/secure-chat",
			userId: session?.user?.email || "unknown",
			ip: extractClientIP(request),
			responseTime,
			metadata: {
				authenticated: !!session,
				errorType:
					error instanceof Error ? error.constructor.name : "unknown",
			},
		});

		if (error instanceof Error && error.message.includes("timeout")) {
			return NextResponse.json(
				{ error: "Request timeout" },
				{ status: 408 }
			);
		}

		if (
			error instanceof Error &&
			error.message.includes("Invalid request")
		) {
			return NextResponse.json({ error: error.message }, { status: 400 });
		}

		return NextResponse.json(
			{ error: "Internal server error" },
			{ status: 500 }
		);
	}
}

export const POST = withLogging(secureChatHandler, "/api/secure-chat");