import config from "../config.json" assert { type: "json" };
import { Hono } from "hono";
import { SignJWT } from "jose";

const KEY_GEN_ALGORITHM = {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: { name: "SHA-256" },
};

const KEY_IMPORT_ALGORITHM = {
    name: "RSASSA-PKCS1-v1_5",
    hash: { name: "SHA-256" },
};

async function loadOrGenerateKeyPair(store: KVNamespace) {
    const keyPairJson = await store.get<{
        publicKey: ArrayBuffer | JsonWebKey;
        privateKey: ArrayBuffer | JsonWebKey;
    }>("keys", { type: "json" });

    if (keyPairJson === null) {
        const keyPair = (await crypto.subtle.generateKey(
            KEY_GEN_ALGORITHM,
            true,
            ["sign", "verify"],
        )) as CryptoKeyPair;
        const privateKey = await crypto.subtle.exportKey(
            "jwk",
            keyPair.privateKey,
        );
        const publicKey = await crypto.subtle.exportKey(
            "jwk",
            keyPair.publicKey,
        );
        await store.put("keys", JSON.stringify({ privateKey, publicKey }));
        return keyPair;
    }

    return {
        publicKey: await crypto.subtle.importKey(
            "jwk",
            keyPairJson.publicKey,
            KEY_IMPORT_ALGORITHM,
            true,
            ["verify"],
        ),
        privateKey: await crypto.subtle.importKey(
            "jwk",
            keyPairJson.privateKey,
            KEY_IMPORT_ALGORITHM,
            true,
            ["sign"],
        ),
    };
}

type Bindings = {
    KEY_CHAIN_store: KVNamespace;
    DISCORD_TOKEN: string;
};

const app = new Hono<{ Bindings: Bindings }>();

app.get("/authorize/:scopemode", async (c) => {
    if (
        c.req.query("client_id") !== config.clientId ||
        c.req.query("redirect_uri") !== config.redirectURL ||
        !["guilds", "email"].includes(c.req.param("scopemode"))
    ) {
        return c.text("", 400);
    }

    const scope =
        c.req.param("scopemode") == "guilds"
            ? "identify email guilds"
            : "identify email";
    const params = new URLSearchParams({
        client_id: config.clientId,
        redirect_uri: config.redirectURL,
        response_type: "code",
        scope,
        state: c.req.query("state"),
        prompt: "none",
    }).toString();

    return c.redirect("https://discord.com/oauth2/authorize?" + params);
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
    }).toString();

    const tokenResponse = await fetch(
        "https://discord.com/api/v10/oauth2/token",
        {
            method: "POST",
            body: params,
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
            },
        },
    );
    if (!tokenResponse.ok) {
        return c.text("", 400);
    }
    const { access_token } = await tokenResponse.json<{
        access_token: string;
    }>();

    const meResponse = await fetch("https://discord.com/api/v10/users/@me", {
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

    const serverResp = await fetch(
        "https://discord.com/api/v10/users/@me/guilds",
        {
            headers: {
                Authorization: `Bearer ${access_token}`,
            },
        },
    );
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
                `https://discord.com/api/v10/guilds/${guildId}/members/${meResult["id"]}`,
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
        .sign((await loadOrGenerateKeyPair(c.env.KEY_CHAIN_store)).privateKey);

    return c.json({
        access_token,
        scope: "identify email",
        id_token: idToken,
    });
});

app.get("/jwks.json", async (c) => {
    const { publicKey } = await loadOrGenerateKeyPair(c.env.KEY_CHAIN_store);
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
