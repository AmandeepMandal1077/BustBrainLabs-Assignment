import { Router } from "express";
import type { Request, Response } from "express";
import axios from "axios";
import { randomBytes, createHash } from "crypto";
import { User } from "../models/User.js";

const router = Router();

const COOKIE_OPTIONS = {
  httpOnly: true,
  maxAge: 5 * 60 * 1000, // 5 minutes
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax" as const,
};

const AIRTABLE_AUTH_URL = "https://airtable.com/oauth2/v1/authorize";
const AIRTABLE_TOKEN_URL = "https://airtable.com/oauth2/v1/token";
const AIRTABLE_WHOAMI_URL = "https://api.airtable.com/v0/meta/whoami";

const SCOPES =
  "data.records:read data.records:write schema.bases:read webhook:manage";

/**
 * GET /auth/login
 * Initiates the OAuth flow. Redirects user to Airtable.
 */
router.get("/login", (req: Request, res: Response) => {
  const state = generateRandomString(16);
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  res.cookie("airtable_oauth_state", state, COOKIE_OPTIONS);
  res.cookie("airtable_code_verifier", codeVerifier, COOKIE_OPTIONS);

  const authUrl = new URL(AIRTABLE_AUTH_URL);
  authUrl.searchParams.set("client_id", process.env.AIRTABLE_CLIENT_ID || "");
  authUrl.searchParams.set("redirect_uri", process.env.REDIRECT_URI || "");
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", SCOPES);
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

/**
 * GET /auth/callback
 * Handles the redirect from Airtable, validates security, and swaps code for token.
 */
router.get("/callback", async (req: Request, res: Response) => {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) {
      return res
        .status(400)
        .json({ error: error_description || "Authorization failed" });
    }

    const savedState = req.cookies.airtable_oauth_state;
    const codeVerifier = req.cookies.airtable_code_verifier;

    if (!state || state !== savedState) {
      return res.status(403).json({ error: "Security Error: State mismatch" });
    }
    if (!codeVerifier) {
      return res
        .status(400)
        .json({ error: "Security Error: Missing code verifier" });
    }
    if (typeof code !== "string") {
      return res.status(400).json({ error: "Invalid authorization code" });
    }

    const encodedCredentials = Buffer.from(
      `${process.env.AIRTABLE_CLIENT_ID}:${process.env.AIRTABLE_CLIENT_SECRET}`
    ).toString("base64");

    const params = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: process.env.REDIRECT_URI || "",
      code_verifier: codeVerifier,
    });

    const tokenRes = await axios.post(AIRTABLE_TOKEN_URL, params.toString(), {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${encodedCredentials}`,
      },
    });

    const { access_token, refresh_token, expires_in } = tokenRes.data;

    const userRes = await axios.get(AIRTABLE_WHOAMI_URL, {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    const airtableId = userRes.data.id;

    const user = await User.findOneAndUpdate(
      { airtableId },
      {
        airtableId,
        accessToken: access_token,
        refreshToken: refresh_token,
        tokenExpiresAt: new Date(Date.now() + expires_in * 1000),
        lastLogin: new Date(),
      },
      { upsert: true, new: true }
    );

    res.clearCookie("airtable_oauth_state");
    res.clearCookie("airtable_code_verifier");

    const clientUrl = process.env.CLIENT_URL || "http://localhost:5173";
    res.redirect(
      `${clientUrl}/dashboard?token=${access_token}&userId=${user._id}`
    );
  } catch (err: any) {
    console.error("Auth Callback Error:", err.response?.data || err.message);
    res.status(500).json({ error: "Authentication failed" });
  }
});

function generateRandomString(length: number) {
  return randomBytes(length).toString("hex");
}

function generateCodeVerifier() {
  return base64UrlEncode(randomBytes(32));
}

function generateCodeChallenge(verifier: string) {
  return base64UrlEncode(createHash("sha256").update(verifier).digest());
}

function base64UrlEncode(buffer: Buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export default router;
