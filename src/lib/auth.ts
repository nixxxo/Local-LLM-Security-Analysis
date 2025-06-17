/* eslint-disable @typescript-eslint/no-explicit-any */
import GoogleProvider from "next-auth/providers/google";
import { logger } from "@/lib/logger";

export const authOptions = {
	providers: [
		GoogleProvider({
			clientId: process.env.GOOGLE_CLIENT_ID || "",
			clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
		}),
	],
	secret: process.env.NEXTAUTH_SECRET,
	callbacks: {
		async signIn({ user, account }: any) {
			try {
				logger.logAuth({
					action: "LOGIN",
					userId: user.email,
					userEmail: user.email,
					provider: account?.provider || "unknown",
					message: `Successful login via ${account?.provider}`,
					metadata: {
						userId: user.id,
						userName: user.name,
						accountType: account?.type,
					},
				});
				return true;
			} catch (error) {
				console.log("auth error", error);
				logger.logError("auth", error as Error);
				return true; // Still allow login even if logging fails
			}
		},
		async jwt({ token, account, user }: any) {
			if (account && user) {
				token.accessToken = account.access_token;
			}
			return token;
		},
		async session({ session }: any) {
			return session;
		},
	},
	events: {
		async signOut({ token }: any) {
			try {
				logger.logAuth({
					action: "LOGOUT",
					userId: token?.email || "unknown",
					userEmail: token?.email,
					message: "User logged out",
				});
			} catch (error) {
				logger.logError("auth", error as Error);
			}
		},
		async signInError(error: any) {
			try {
				logger.logAuth({
					action: "LOGIN_FAILED",
					message: "Login attempt failed",
					metadata: {
						error: error.message,
						errorType: error.type || "unknown",
					},
				});
			} catch (logError) {
				logger.logError("auth", logError as Error);
			}
		},
	},
};
