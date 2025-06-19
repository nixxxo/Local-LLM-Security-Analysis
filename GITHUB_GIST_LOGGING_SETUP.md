# GitHub Gist Logging Setup Guide

This guide will help you set up GitHub Gist-based logging for your Local LLM application. This solution works universally on both localhost and Vercel deployments with zero infrastructure costs.

## Overview

Your logging system now uses GitHub Gists as a universal storage backend:

-   ✅ **100% Free** - No costs for reasonable usage
-   ✅ **Universal** - Works identically on localhost and Vercel
-   ✅ **Version Control** - Automatic versioning of log files
-   ✅ **Web Interface** - View logs directly on GitHub
-   ✅ **Zero Infrastructure** - No databases or external services

## Prerequisites

1. **GitHub Account** - You need a GitHub account
2. **GitHub Personal Access Token** - For API access

## Step 1: Create GitHub Personal Access Token

1. Go to [GitHub Settings → Personal Access Tokens](https://github.com/settings/tokens)
2. Click **Generate new token** → **Generate new token (classic)**
3. Give it a descriptive name: `local-llm-logging`
4. Set expiration (recommend 1 year)
5. Select scopes:
    - ✅ **gist** - Create and modify gists
6. Click **Generate token**
7. **Copy the token immediately** - you won't see it again!

## Step 2: Set Environment Variables

Add this environment variable to your project:

### For Local Development (.env.local)

```bash
# GitHub Personal Access Token for Gist logging
GITHUB_TOKEN=ghp_your_token_here
```

### For Vercel Deployment

1. Go to your Vercel project dashboard
2. Navigate to **Settings** → **Environment Variables**
3. Add:
    - **Name**: `GITHUB_TOKEN`
    - **Value**: `ghp_your_token_here`
    - **Environment**: Production, Preview, Development

## Step 3: Initialize Logging (Optional)

The system will automatically create gists when first used, but you can initialize them manually:

### Option A: Using the API Endpoint

```bash
# Test the logging system
curl -X POST http://localhost:3000/api/gist-logs \
  -H "Content-Type: application/json" \
  -d '{"action": "test"}'
```

### Option B: Trigger Logs Through Usage

Just use your application normally - logs will be created automatically.

## Step 4: Verify Setup

Check if everything is working:

```bash
# Health check
curl http://localhost:3000/api/gist-logs?action=health

# Get gist URLs
curl http://localhost:3000/api/gist-logs?action=urls
```

## Log Structure

Logs are stored in separate GitHub Gists by type:

-   **API Logs**: HTTP requests, responses, performance
-   **Auth Logs**: Login/logout events, authentication failures
-   **Chat Logs**: LLM interactions, token usage
-   **Error Logs**: Application errors and exceptions
-   **General Logs**: Miscellaneous application events

Each gist contains a JSON structure:

```json
{
	"logs": [
		{
			"timestamp": "2024-01-15T10:30:00.000Z",
			"level": "INFO",
			"service": "api",
			"message": "GET /api/users",
			"endpoint": "/api/users",
			"method": "GET",
			"statusCode": 200,
			"responseTime": 150,
			"userEmail": "user@example.com"
		}
	],
	"lastUpdated": "2024-01-15T10:30:00.000Z",
	"maxSize": 1000,
	"version": "1.0.0"
}
```

## Gist Management

### Automatic Gist Creation

When your application first logs an event of each type, it will:

1. Create a new private gist
2. Log the gist ID to console
3. Provide the environment variable you should add

Example output:

```
Created new gist for api logs: abc123def456
Add this to your environment variables: GITHUB_GIST_API=abc123def456
```

### Manual Gist IDs (Optional)

If you want to pre-create gists or use specific ones, add these environment variables:

```bash
# Optional: Specify gist IDs manually
GITHUB_GIST_API=your_api_gist_id
GITHUB_GIST_AUTH=your_auth_gist_id
GITHUB_GIST_CHAT=your_chat_gist_id
GITHUB_GIST_ERROR=your_error_gist_id
GITHUB_GIST_GENERAL=your_general_gist_id
```

## Features

### Batching

-   Logs are batched for efficiency (10 logs per batch)
-   Automatic flush every 5 seconds
-   Immediate flush when batch is full

### Log Rotation & Cleanup

-   **Maximum 500 logs per gist** (reduced for efficiency and cost control)
-   **Automatic age-based cleanup** (removes logs older than 7 days)
-   **Size-based rotation** (keeps most recent logs when limit reached)
-   **Automatic cleanup** prevents gists from growing too large
-   **Smart rotation** prioritizes recent logs over old ones

### Fallback

-   Falls back to console logging if GitHub API fails
-   Graceful error handling
-   No application blocking

## API Endpoints

### GET /api/gist-logs

**Health Check**

```bash
GET /api/gist-logs?action=health
```

**Get Gist URLs**

```bash
GET /api/gist-logs?action=urls
```

**Get Storage Statistics**

```bash
GET /api/gist-logs?action=stats
```

**Force Flush Logs**

```bash
GET /api/gist-logs?action=flush
```

### POST /api/gist-logs

**Test Logging**

```bash
POST /api/gist-logs
Content-Type: application/json

{
  "action": "test"
}
```

**Force Flush Logs**

```bash
POST /api/gist-logs
Content-Type: application/json

{
  "action": "flush"
}
```

## Monitoring and Access

### View Logs

1. Get gist URLs: `GET /api/gist-logs?action=urls`
2. Visit the GitHub gist URLs directly
3. Use the built-in monitoring dashboard at `/monitoring`

### Log Analysis

-   Use GitHub's built-in gist versioning to see log history
-   Download gist content as JSON for analysis
-   Use the `/api/logs` endpoint to query logs programmatically

### Storage Monitoring

Monitor your gist storage usage:

```bash
GET /api/gist-logs?action=stats
```

Response includes:

```json
{
	"success": true,
	"data": {
		"gistStats": {
			"api": {
				"count": 245,
				"size": "12.4 KB",
				"url": "https://gist.github.com/abc123"
			},
			"auth": {
				"count": 89,
				"size": "4.2 KB",
				"url": "https://gist.github.com/def456"
			}
		}
	}
}
```

## Troubleshooting

### Common Issues

**"GITHUB_TOKEN not configured"**

-   Ensure you've set the `GITHUB_TOKEN` environment variable
-   Verify the token has `gist` permissions

**"GitHub API access failed"**

-   Check if your token is valid and not expired
-   Verify your GitHub account has gist permissions
-   Check rate limits (5000 requests/hour for authenticated users)

**"Failed to create gist"**

-   Ensure your GitHub account can create gists
-   Check if you've hit gist limits (no official limit, but be reasonable)

### Debug Mode

Enable debug logging:

```bash
NODE_ENV=development npm run dev
```

### Health Check

```bash
curl http://localhost:3000/api/gist-logs?action=health
```

Example healthy response:

```json
{
	"success": true,
	"data": {
		"healthy": true,
		"issues": []
	}
}
```

## Performance Considerations

-   **Write Performance**: Batched writes reduce API calls
-   **Read Performance**: Direct GitHub API access
-   **Rate Limits**: 5000 requests/hour (very generous)
-   **Storage Limits**: 1000 logs per gist, 7-day retention
-   **Auto Cleanup**: Old logs automatically removed to control size
-   **Cost Control**: Smart limits prevent unexpected growth

## Security

-   **Private Gists**: All gists are created as private
-   **Token Security**: Store tokens securely, rotate regularly
-   **Access Control**: Only authenticated users can access log APIs
-   **Data Privacy**: Logs stay in your GitHub account

## Migration from Previous System

The migration is automatic:

-   Remove `@vercel/edge-config` dependency ✅
-   Remove Edge Config environment variables
-   Remove local log files (they won't be used)
-   Add `GITHUB_TOKEN` environment variable

## Best Practices

1. **Token Management**: Rotate tokens regularly
2. **Monitor Usage**: Check gist sizes occasionally
3. **Error Handling**: Monitor health check endpoint
4. **Backup**: Gists are automatically versioned by GitHub
5. **Access Control**: Keep gists private for sensitive data

## Cost Analysis

**GitHub Gist**: FREE

-   Unlimited private gists
-   5000 API requests/hour
-   Automatic versioning and backup
-   Global CDN access

**Total Cost**: $0.00/month 🎉

## Support

If you encounter issues:

1. Check the health endpoint: `/api/gist-logs?action=health`
2. Verify environment variables are set correctly
3. Check GitHub token permissions
4. Review application logs for error messages

## API Reference

### Logger Methods

```typescript
// API request logging
logger.logApi({
	method: "GET",
	endpoint: "/api/users",
	statusCode: 200,
	responseTime: 150,
	userEmail: "user@example.com",
});

// Authentication events
logger.logAuth({
	action: "LOGIN",
	provider: "github",
	userEmail: "user@example.com",
});

// Chat interactions
logger.logChat({
	model: "gpt-4",
	tokens: { prompt: 100, completion: 200, total: 300 },
	userEmail: "user@example.com",
});

// Error logging
logger.logError("api", new Error("Something went wrong"));

// General information
logger.logInfo("app", "Application started");
```

### Utility Methods

```typescript
// Force flush pending logs
await logger.flush();

// Get gist URLs
const urls = logger.getGistUrls();

// Health check
const health = await logger.healthCheck();
```

This setup provides a robust, free, and universal logging solution that works seamlessly across all deployment environments!
