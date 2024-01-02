import { Hono } from "hono";
import { SignJWT } from "jose";

import * as config from "../config.json" assert { type: "json" };
import { KVKeyStore } from "./adaptor/kv";
import { loadOrGenerateKeyPair } from "./key";

const DISCORD_API_ROOT = "https://discord.com/api/v10";

type Bindings = {
    KEY_CHAIN_KV: KVNamespace;
    DISCORD_TOKEN: string;
};

const app = new Hono<{ Bindings: Bindings }>();

app.get("/authorize/:scope_mode", async (c) => {
    const SCOPE_MODES = ["guilds", "email"];
    if (
        c.req.query("client_id") !== config.clientId ||
        c.req.query("redirect_uri") !== config.redirectURL ||
        !SCOPE_MODES.includes(c.req.param("scope_mode"))
    ) {
        return c.text("", 400);
    }

    const scope =
        c.req.param("scope_mode") == "guilds"
            ? "identify email guilds"
            : "identify email";
    const params = new URLSearchParams({
        client_id: config.clientId,
        redirect_uri: config.redirectURL,
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
        client_id: config.clientId,
        client_secret: config.clientSecret,
        redirect_uri: config.redirectURL,
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
        verified: unknown;
        id: string;
        preferred_name: string;
        email: string;
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

    if (c.env.DISCORD_TOKEN && "serversToCheckRolesFor" in config) {
        for (const guildId of config.serversToCheckRolesFor) {
            if (!servers.includes(guildId)) {
                continue;
            }
            const memberResponse = await fetch(
                `${DISCORD_API_ROOT}/guilds/${guildId}/members/${meResult["id"]}`,
                {
                    headers: {
                        Authorization: `Bot ${c.env.DISCORD_TOKEN}`,
                    },
                },
            );
            const { roles } = await memberResponse.json<{
                roles: string[];
            }>();
            roleClaims[`roles:${guildId}`] = roles;
        }
    }

    const { privateKey } = await loadOrGenerateKeyPair(
        new KVKeyStore(c.env.KEY_CHAIN_KV),
    );
    const idToken = await new SignJWT({
        iss: "https://cloudflare.com",
        aud: config.clientId,
        ...meResult,
        ...roleClaims,
        guilds: servers,
    })
        .setProtectedHeader({ alg: "RS256" })
        .setExpirationTime("1h")
        .setAudience(config.clientId)
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
