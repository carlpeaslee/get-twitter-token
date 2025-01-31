import { serve } from "bun"
import { randomBytes } from "node:crypto"
// Your app's credentials - replace these with your actual values
const CLIENT_ID = process.env.X_CLIENT_ID as string
const CLIENT_SECRET = process.env.X_CLIENT_SECRET as string
const REDIRECT_URI = "http://localhost:3000/callback"
const SCOPES = ["tweet.read", "tweet.write", "users.read"].join(" ")

// Store the state and code verifier
const state = randomBytes(16).toString("hex")
const codeVerifier = randomBytes(32).toString("base64url")

// Generate the code challenge from the code verifier
async function generateCodeChallenge(verifier: string) {
	const encoder = new TextEncoder()
	const data = encoder.encode(verifier)
	const hash = await crypto.subtle.digest("SHA-256", data)
	return btoa(String.fromCharCode(...new Uint8Array(hash)))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "")
}

// Create the authorization URL
const authUrl = new URL("https://twitter.com/i/oauth2/authorize")
authUrl.searchParams.append("response_type", "code")
authUrl.searchParams.append("client_id", CLIENT_ID)
authUrl.searchParams.append("redirect_uri", REDIRECT_URI)
authUrl.searchParams.append("scope", SCOPES)
authUrl.searchParams.append("state", state)
authUrl.searchParams.append("code_challenge_method", "S256")
authUrl.searchParams.append(
	"code_challenge",
	await generateCodeChallenge(codeVerifier),
)

// Start a local server to handle the OAuth callback
const server = serve({
	port: 3000,
	async fetch(req) {
		const url = new URL(req.url)

		if (url.pathname === "/callback") {
			const params = url.searchParams
			const code = params.get("code")
			const returnedState = params.get("state")

			// Verify state parameter
			if (returnedState !== state) {
				return new Response("Invalid state parameter", { status: 400 })
			}

			if (code) {
				try {
					// Exchange the authorization code for tokens using the same code verifier
					const tokenResponse = await fetch(
						"https://api.twitter.com/2/oauth2/token",
						{
							method: "POST",
							headers: {
								"Content-Type": "application/x-www-form-urlencoded",
								Authorization: `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")}`,
							},
							body: new URLSearchParams({
								grant_type: "authorization_code",
								code,
								redirect_uri: REDIRECT_URI,
								code_verifier: codeVerifier, // Use the stored code verifier
							}),
						},
					)

					const tokens = await tokenResponse.json()
					console.log(tokens)
					if (tokens.error) {
						console.error("Token Error:", tokens)
						return new Response(
							`Error: ${tokens.error} - ${tokens.error_description}`,
							{ status: 400 },
						)
					}

					console.log("Access Token:", tokens.access_token)
					console.log("Refresh Token:", tokens.refresh_token)

					// Stop the server after getting the tokens
					setTimeout(() => process.exit(0), 1000)

					return new Response(
						"Authorization successful! You can close this window.",
					)
				} catch (error) {
					console.error("Error exchanging code for tokens:", error)
					return new Response("Error getting access token", { status: 500 })
				}
			}
		}

		return new Response("Not found", { status: 404 })
	},
})

// Open the authorization URL in the default browser
console.log("Opening auth URL in browser...")
console.log(authUrl.toString())
await Bun.spawn(["open", authUrl.toString()])

console.log("Waiting for authorization...")
