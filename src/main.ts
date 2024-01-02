import { Hono } from "hono";
import { SignJWT } from "jose";

import { KVKeyStore } from "./adaptor/kv";
import { loadOrGenerateKeyPair } from "./key";

const DISCORD_API_ROOT = "https://discord.com/api/v10";
const DISCORD_CLIENT_ID = "1191642657731121272";
const DISCORD_CHECK_GUILD_ID = "683939861539192860";

const CLOUDFLARE_ACCESS_REDIRECT_URI =
    "https://approvers.cloudflareaccess.com/cdn-cgi/access/callback";

type Bindings = {
    KEY_CHAIN_KV: KVNamespace;
    DISCORD_TOKEN: string;
    DISCORD_CLIENT_SECRET: string;
};

const app = new Hono<{ Bindings: Bindings }>();

app.get("/authorize/:scope_mode", async (c) => {
    const SCOPE_MODES = ["guilds", "email"];
    if (
        c.req.query("client_id") !== DISCORD_CLIENT_ID ||
        c.req.query("redirect_uri") !== CLOUDFLARE_ACCESS_REDIRECT_URI ||
        !SCOPE_MODES.includes(c.req.param("scope_mode"))
    ) {
        return c.text("", 400);
    }

    const scope =
        c.req.param("scope_mode") == "guilds"
            ? "identify email guilds"
            : "identify email";
    const params = new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        redirect_uri: CLOUDFLARE_ACCESS_REDIRECT_URI,
        response_type: "code",
        scope,
        state: c.req.query("state") ?? "",
        prompt: "none",
    });

    return c.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

app.post("/token", async (c) => {
    const body = await c.req.parseBody();

    const code = body.code;
    const params = new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: c.env.DISCORD_CLIENT_SECRET,
        redirect_uri: CLOUDFLARE_ACCESS_REDIRECT_URI,
        code: code.toString(),
        grant_type: "authorization_code",
        scope: "identify email",
    });

    const tokenResponse = await fetch(`${DISCORD_API_ROOT}/oauth2/token`, {
        method: "POST",
        body: params,
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
    });
    if (!tokenResponse.ok) {
        return c.text("", 400);
    }
    const { access_token } = await tokenResponse.json<{
        access_token: string;
    }>();

    const meResponse = await fetch(`${DISCORD_API_ROOT}/users/@me`, {
        headers: {
            Authorization: `Bearer ${access_token}`,
        },
    });
    if (!meResponse.ok) {
        meResponse.text().then(console.error);
        return c.text("", 500);
    }
    const meResult = await meResponse.json<{
        id: string;
        username: string;
        discriminator: string;
        global_name?: string;
        verified?: boolean;
        email?: string;
        [key: `roles:${string}`]: string;
    }>();

    if (!meResult.verified) {
        return c.text("", 400);
    }

    const servers: string[] = [];

    const serverResp = await fetch(`${DISCORD_API_ROOT}/users/@me/guilds`, {
        headers: {
            Authorization: `Bearer ${access_token}`,
        },
    });
    if (serverResp.status === 200) {
        const serverJson = await serverResp.json<{ id: string }[]>();
        servers.push(...serverJson.map(({ id }) => id));
    }

    const roleClaims: { [key: `roles:${string}`]: string[] } = {};

    if (servers.includes(DISCORD_CHECK_GUILD_ID)) {
        const memberResponse = await fetch(
            `${DISCORD_API_ROOT}/guilds/${DISCORD_CHECK_GUILD_ID}/members/${meResult.id}`,
            {
                headers: {
                    Authorization: `Bot ${c.env.DISCORD_TOKEN}`,
                },
            },
        );
        const { roles } = await memberResponse.json<{
            roles: string[];
        }>();
        roleClaims[`roles:${DISCORD_CHECK_GUILD_ID}`] = roles;
    }

    const { privateKey } = await loadOrGenerateKeyPair(
        new KVKeyStore(c.env.KEY_CHAIN_KV),
    );
    const idToken = await new SignJWT({
        iss: "https://cloudflare.com",
        aud: DISCORD_CLIENT_ID,
        ...meResult,
        ...roleClaims,
        guilds: servers,
    })
        .setProtectedHeader({ alg: "RS256" })
        .setExpirationTime("1h")
        .setAudience(DISCORD_CLIENT_ID)
        .sign(privateKey);

    return c.json({
        access_token,
        scope: "identify email",
        id_token: idToken,
    });
});

app.get("/jwks.json", async (c) => {
    const { publicKey } = await loadOrGenerateKeyPair(
        new KVKeyStore(c.env.KEY_CHAIN_KV),
    );
    return c.json({
        keys: [
            {
                alg: "RS256",
                kid: "jwtRS256",
                ...(await crypto.subtle.exportKey("jwk", publicKey)),
            },
        ],
    });
});

export default app;
