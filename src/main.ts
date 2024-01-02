import * as config from "../config.json" assert { type: "json" };
import { Hono } from "hono";
import * as jose from "jose";

const algorithm = {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: { name: "SHA-256" },
};

const importAlgo = {
    name: "RSASSA-PKCS1-v1_5",
    hash: { name: "SHA-256" },
};

async function loadOrGenerateKeyPair(store: KVNamespace) {
    const keyPairJson = await store.get<{
        publicKey: ArrayBuffer | JsonWebKey;
        privateKey: ArrayBuffer | JsonWebKey;
    }>("keys", { type: "json" });

    if (keyPairJson !== null) {
        const keyPair = {
            publicKey: await crypto.subtle.importKey(
                "jwk",
                keyPairJson.publicKey,
                importAlgo,
                true,
                ["verify"],
            ),
            privateKey: await crypto.subtle.importKey(
                "jwk",
                keyPairJson.privateKey,
                importAlgo,
                true,
                ["sign"],
            ),
        };

        return keyPair;
    }
    const keyPair = (await crypto.subtle.generateKey(algorithm, true, [
        "sign",
        "verify",
    ])) as CryptoKeyPair;

    await store.put(
        "keys",
        JSON.stringify({
            privateKey: await crypto.subtle.exportKey(
                "jwk",
                keyPair.privateKey,
            ),
            publicKey: await crypto.subtle.exportKey("jwk", keyPair.publicKey),
        }),
    );

    return keyPair;
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
        return c.text("Bad request.", 400);
    }

    const params = new URLSearchParams({
        client_id: config.clientId,
        redirect_uri: config.redirectURL,
        response_type: "code",
        scope:
            c.req.param("scopemode") == "guilds"
                ? "identify email guilds"
                : "identify email",
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

    const r = await fetch("https://discord.com/api/v10/oauth2/token", {
        method: "POST",
        body: params,
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
    }).then((res) => res.json<{ access_token: string }>());

    if (r === null) {
        return new Response("Bad request.", { status: 400 });
    }
    const userInfo = await fetch("https://discord.com/api/v10/users/@me", {
        headers: {
            Authorization: "Bearer " + r["access_token"],
        },
    }).then((res) =>
        res.json<{
            verified: unknown;
            id: string;
            preferred_name: string;
            email: string;
            [key: `roles:${string}`]: string;
        }>(),
    );

    if (!userInfo["verified"]) return c.text("Bad request.", 400);

    let servers: string[] = [];

    const serverResp = await fetch(
        "https://discord.com/api/v10/users/@me/guilds",
        {
            headers: {
                Authorization: "Bearer " + r["access_token"],
            },
        },
    );

    if (serverResp.status === 200) {
        const serverJson = await serverResp.json<{ id: string }[]>();
        servers = serverJson.map((item) => {
            return item["id"];
        });
    }

    const roleClaims: { [key: `roles:${string}`]: string[] } = {};

    if (c.env.DISCORD_TOKEN && "serversToCheckRolesFor" in config) {
        await Promise.all(
            config.serversToCheckRolesFor.map(async (guildId) => {
                if (servers.includes(guildId)) {
                    let memberPromise = fetch(
                        `https://discord.com/api/v10/guilds/${guildId}/members/${userInfo["id"]}`,
                        {
                            headers: {
                                Authorization: "Bot " + c.env.DISCORD_TOKEN,
                            },
                        },
                    );
                    // i had issues doing this any other way?
                    const memberResp = await memberPromise;
                    const memberJson = await memberResp.json<{
                        roles: string[];
                    }>();

                    roleClaims[`roles:${guildId}`] = memberJson.roles;
                }
            }),
        );
    }

    let preferred_username = userInfo["preferred_name"];

    const idToken = await new jose.SignJWT({
        iss: "https://cloudflare.com",
        aud: config.clientId,
        preferred_username,
        ...userInfo,
        ...roleClaims,
        email: userInfo["email"],
        guilds: servers,
    })
        .setProtectedHeader({ alg: "RS256" })
        .setExpirationTime("1h")
        .setAudience(config.clientId)
        .sign((await loadOrGenerateKeyPair(c.env.KEY_CHAIN_store)).privateKey);

    return c.json({
        ...r,
        scope: "identify email",
        id_token: idToken,
    });
});

app.get("/jwks.json", async (c) => {
    let publicKey = (await loadOrGenerateKeyPair(c.env.KEY_CHAIN_store))
        .publicKey;
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
