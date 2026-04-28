import { Hono } from 'hono'
import { cors } from 'hono/cors'

const app = new Hono()

const AUTH_BASE_URL = "https://prelive-oauth2.quran.foundation"
const JWKS_URL = `${AUTH_BASE_URL}/.well-known/jwks.json`

// Cache JWKS biar tidak fetch terus
let jwksCache: any = null
let jwksFetchedAt = 0
const JWKS_TTL = 60 * 60 * 1000 // 1 jam

async function getJWKS() {
  if (jwksCache && Date.now() - jwksFetchedAt < JWKS_TTL) {
    return jwksCache
  }

  const res = await fetch(JWKS_URL)
  if (!res.ok) throw new Error("Failed to fetch JWKS")

  jwksCache = await res.json()
  jwksFetchedAt = Date.now()

  return jwksCache
}

// Convert base64url → ArrayBuffer
function base64urlToArrayBuffer(base64url: string) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

async function verifyJWT(token: string) {
  const [headerB64, payloadB64, signatureB64] = token.split('.')

  const header = JSON.parse(atob(headerB64))
  const payload = JSON.parse(atob(payloadB64))

  const jwks = await getJWKS()
  const key = jwks.keys.find((k: any) => k.kid === header.kid)

  if (!key) throw new Error("Public key not found")

  const cryptoKey = await crypto.subtle.importKey(
    "jwk",
    key,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["verify"]
  )

  const data = new TextEncoder().encode(`${headerB64}.${payloadB64}`)
  const signature = base64urlToArrayBuffer(signatureB64)

  const isValid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    signature,
    data
  )

  if (!isValid) throw new Error("Invalid JWT signature")

  // Optional: validate exp
  if (payload.exp && Date.now() / 1000 > payload.exp) {
    throw new Error("Token expired")
  }

  return payload
}

// CORS (restrict origin di production!)
app.use('*', cors({
  origin: '*', // ganti dengan domain app kamu
  allowMethods: ['POST', 'OPTIONS'],
  allowHeaders: ['Content-Type'],
}))

app.post('/api/auth/qf/exchange', async (c: any) => {
  try {
    const body = await c.req.json()

    const { code, codeVerifier, redirectUri } = body

    // ✅ Validasi input
    if (!code || !codeVerifier || !redirectUri) {
      return c.json({ error: "Missing required fields" }, 400)
    }

    const params = new URLSearchParams()
    params.append("grant_type", "authorization_code")
    params.append("code", code)
    params.append("redirect_uri", redirectUri)
    params.append("code_verifier", codeVerifier)

    const clientId = c.env.QF_CLIENT_ID
    const clientSecret = c.env.QF_CLIENT_SECRET

    if (!clientId || !clientSecret) {
      return c.json({ error: "Server misconfigured" }, 500)
    }

    const basicAuth = btoa(`${clientId}:${clientSecret}`)

    const tokenResponse = await fetch(
      `${AUTH_BASE_URL}/oauth2/token`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Authorization": `Basic ${basicAuth}`,
        },
        body: params.toString(),
      }
    )

    const rawText = await tokenResponse.text()

    if (!tokenResponse.ok) {
      return c.json({
        error: "Token exchange failed",
        detail: rawText,
      }, 502)
    }

    const token = JSON.parse(rawText)

    let user = null

    if (token.id_token) {
      try {
        user = await verifyJWT(token.id_token)
      } catch (err) {
        return c.json({
          error: "Invalid ID token",
          detail: err instanceof Error ? err.message : "Unknown error"
        }, 401)
      }
    }

    return c.json({
      accessToken: token.access_token,
      refreshToken: token.refresh_token,
      idToken: token.id_token,
      expiresIn: token.expires_in,
      user,
    })

  } catch (error) {
    return c.json({
      error: "Internal server error",
      detail: error instanceof Error ? error.message : "Unknown"
    }, 500)
  }
})

export default app