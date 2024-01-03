import { Result } from "@mikuroxina/mini-fn";
import { Hono } from "hono";

import { generateToken, me, rolesOf } from "./adaptor/discord";
import { KVKeyStore } from "./adaptor/kv";
import { loadOrGenerateKeyPair } from "./service/key";
import { token } from "./service/token";

const DISCORD_CLIENT_ID = "1191642657731121272";

const CLOUDFLARE_ACCESS_REDIRECT_URI =
    "https://approvers.cloudflareaccess.com/cdn-cgi/access/callback";

type Bindings = {
    KEY_CHAIN_KV: KVNamespace;
    DISCORD_TOKEN: string;
    DISCORD_CLIENT_SECRET: string;
};

const app = new Hono<{ Bindings: Bindings }>();

app.get("/authorize", async (c) => {
    if (
        c.req.query("client_id") !== DISCORD_CLIENT_ID ||
        c.req.query("redirect_uri") !== CLOUDFLARE_ACCESS_REDIRECT_URI
    ) {
        return c.text("", 400);
    }
    const params = new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        redirect_uri: CLOUDFLARE_ACCESS_REDIRECT_URI,
        response_type: "code",
        scope: "identify email guilds",
        state: c.req.query("state") ?? "",
        prompt: "none",
    });

    return c.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

app.post("/token", async (c) => {
    const body = await c.req.parseBody();
    const code = body.code;

    const res = await token({
        code: code.toString(),
        generateToken: generateToken(c.env.DISCORD_CLIENT_SECRET),
        me,
        rolesOf: rolesOf(c.env.DISCORD_TOKEN),
        getKeyPair: () =>
            loadOrGenerateKeyPair(new KVKeyStore(c.env.KEY_CHAIN_KV)),
    });
    if (Result.isErr(res)) {
        switch (res[1]) {
            case "TOKEN_GEN_FAILURE":
                return c.text("", 500);
            case "NOT_VERIFIED":
                return c.text("email not verified", 400);
        }
    }

    const { oAuthToken, jwt } = res[1];
    return c.json({
        ...oAuthToken,
        scope: "identify email",
        id_token: jwt,
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
