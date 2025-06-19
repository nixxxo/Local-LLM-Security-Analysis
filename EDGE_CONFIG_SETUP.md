# Edge Config Logging Setup Guide

This guide will help you set up Vercel Edge Config for logging when your application is deployed on Vercel, while maintaining file-based logging for local development.

## Overview

Your logging system now automatically detects if it's running on Vercel and switches between:

-   **Local Development**: File-based logging (existing behavior)
-   **Vercel Deployment**: Edge Config-based logging (new feature)

## Prerequisites

1. **Vercel Account**: You need a Vercel account with a project deployed
2. **Edge Config**: Create an Edge Config in your Vercel dashboard
3. **API Token**: Generate a Vercel API token for write operations

## Step 1: Create Edge Config

1. Go to your Vercel dashboard
2. Navigate to **Storage** → **Edge Config**
3. Click **Create Edge Config**
4. Name it something like `app-logs`
5. Copy the **Edge Config ID** and **Connection String**

## Step 2: Set Environment Variables

Add these environment variables to your Vercel project:

### Required Variables

```bash
# Edge Config connection string (from Vercel dashboard)
EDGE_CONFIG=edge-config://your-edge-config-id.vercel-storage.com

# Edge Config ID (from Vercel dashboard)
EDGE_CONFIG_ID=your-edge-config-id

# Vercel API token (for write operations)
VERCEL_OIDC_TOKEN=your-vercel-api-token
```

### How to Get Vercel API Token

1. Go to [Vercel Account Settings](https://vercel.com/account/tokens)
2. Click **Create Token**
3. Give it a name like `edge-config-logging`
4. Select appropriate scopes (needs Edge Config write access)
5. Copy the token and add it to your environment variables

## Step 3: Initialize Edge Config

After deploying with the environment variables, initialize the Edge Config structure:

### Option A: Using the API Endpoint

```bash
curl -X POST https://your-app.vercel.app/api/edge-config \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN" \
  -d '{"action": "initialize"}'
```

### Option B: Using the Setup Utility

```typescript
import { initializeEdgeConfigForLogs } from "@/lib/edge-config-setup";

const result = await initializeEdgeConfigForLogs();
console.log(result);
```

## Step 4: Verify Setup

Check if everything is working correctly:

```bash
# Check health
curl https://your-app.vercel.app/api/edge-config?action=health

# Check stats
curl https://your-app.vercel.app/api/edge-config?action=stats
```

## Environment Detection

The system automatically detects the environment:

```typescript
// In your code
import { logger } from "@/lib/logger";

// This will automatically use Edge Config on Vercel, files locally
logger.logApi({
	method: "GET",
	endpoint: "/api/test",
	statusCode: 200,
	responseTime: 150,
});

// Check which environment you're in
if (logger.isRunningOnVercel()) {
	console.log("Using Edge Config for logging");
} else {
	console.log("Using file system for logging");
}
```

## Log Structure in Edge Config

Logs are stored in Edge Config with the following structure:

```json
{
	"logs_api": {
		"logs": [
			{
				"timestamp": "2024-01-15T10:30:00.000Z",
				"level": "INFO",
				"service": "api",
				"method": "GET",
				"endpoint": "/api/users",
				"statusCode": 200,
				"responseTime": 150,
				"userEmail": "user@example.com",
				"message": "GET /api/users"
			}
		],
		"lastUpdated": "2024-01-15T10:30:00.000Z",
		"maxSize": 1000
	},
	"logs_auth": {
		/* auth logs */
	},
	"logs_chat": {
		/* chat logs */
	},
	"logs_error": {
		/* error logs */
	},
	"logs_general": {
		/* general logs */
	}
}
```

## Log Rotation and Cleanup

Edge Config has storage limits, so logs are automatically rotated:

-   **Maximum logs per type**: 1000 (configurable)
-   **Automatic cleanup**: Keeps most recent logs when limit is reached
-   **Manual cleanup**: Use the cleanup API

### Manual Cleanup

```bash
# Clean up logs older than 7 days
curl -X POST https://your-app.vercel.app/api/edge-config \
  -H "Content-Type: application/json" \
  -d '{"action": "cleanup", "daysToKeep": 7}'
```

## Monitoring Edge Config Usage

Monitor your Edge Config usage:

```bash
# Get usage statistics
curl https://your-app.vercel.app/api/edge-config?action=stats
```

Response:

```json
{
	"success": true,
	"data": {
		"totalLogs": 2450,
		"logsByType": {
			"api": 1200,
			"auth": 300,
			"chat": 800,
			"error": 50,
			"general": 100
		},
		"oldestLog": "2024-01-08T09:15:00.000Z",
		"newestLog": "2024-01-15T14:30:00.000Z",
		"storageEfficiency": 49.0
	}
}
```

## Troubleshooting

### Common Issues

1. **"Edge Config not available"**: Check if `EDGE_CONFIG` environment variable is set
2. **"Cannot update Edge Config"**: Verify `VERCEL_OIDC_TOKEN` has correct permissions
3. **"EDGE_CONFIG_ID not set"**: Add the Edge Config ID to environment variables

### Health Check

```bash
curl https://your-app.vercel.app/api/edge-config?action=health
```

Example response:

```json
{
	"success": true,
	"data": {
		"healthy": true,
		"issues": [],
		"recommendations": []
	}
}
```

### Debug Mode

Enable debug logging in development:

```bash
NODE_ENV=development npm run dev
```

## Performance Considerations

-   **Read Performance**: Edge Config reads are extremely fast (~1ms)
-   **Write Performance**: Writes require API calls and may have latency
-   **Storage Limits**: Monitor your usage to avoid hitting limits
-   **Batch Operations**: Consider batching log writes for high-traffic applications

## Migration from File-based Logging

The migration is automatic:

-   **Local development**: Continues using files
-   **Vercel deployment**: Automatically switches to Edge Config
-   **Existing logs**: Remain in files, new logs go to Edge Config

## Best Practices

1. **Monitor Usage**: Regularly check Edge Config statistics
2. **Clean Up Regularly**: Set up automated cleanup for old logs
3. **Environment Variables**: Keep API tokens secure and rotate them regularly
4. **Error Handling**: The system gracefully falls back to console logging if Edge Config fails
5. **Testing**: Test both local and Vercel environments

## API Reference

### GET /api/edge-config

-   `?action=health` - Check Edge Config health
-   `?action=stats` - Get usage statistics

### POST /api/edge-config

-   `{"action": "initialize"}` - Initialize Edge Config structure
-   `{"action": "cleanup", "daysToKeep": 7}` - Clean up old logs

## Support

If you encounter issues:

1. Check the health endpoint
2. Verify environment variables
3. Check Vercel dashboard for Edge Config status
4. Review application logs for error messages

## Edge Config Limits

-   **Storage**: 512KB per Edge Config
-   **Keys**: 1000 keys maximum
-   **Read Operations**: Unlimited
-   **Write Operations**: Rate limited (check Vercel documentation)

For more information, see the [Vercel Edge Config documentation](https://vercel.com/docs/storage/edge-config).
