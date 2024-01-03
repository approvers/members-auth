import { Result } from "@mikuroxina/mini-fn";

import {
    CLOUDFLARE_ACCESS_REDIRECT_URI,
    DISCORD_API_ROOT,
    DISCORD_CLIENT_ID,
} from "../consts";
import type { Token, TokenResult, User } from "../service/token";

export const generateToken =
    (clientSecret: string) =>
    async (code: string): Promise<TokenResult<Token>> => {
        const params = new URLSearchParams({
            client_id: DISCORD_CLIENT_ID,
            client_secret: clientSecret,
            redirect_uri: CLOUDFLARE_ACCESS_REDIRECT_URI,
            code,
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
            console.log(params);
            console.log(tokenResponse.status);
            console.log(await tokenResponse.text());
            return Result.err("TOKEN_GEN_FAILURE");
        }
        const tokenResult = await tokenResponse.json<{
            access_token: string;
            token_type: string;
            expires_in: number;
            refresh_token: string;
            scope: string;
        }>();
        return Result.ok(tokenResult);
    };

export const me = async (accessToken: string): Promise<User> => {
    const meResponse = await fetch(`${DISCORD_API_ROOT}/users/@me`, {
        headers: {
            Authorization: `Bearer ${accessToken}`,
        },
    });
    if (!meResponse.ok) {
        console.log(meResponse.status);
        console.log(await meResponse.text());
        throw new Error("failed to get user info");
    }

    const meResult = await meResponse.json<{
        id: string;
        username: string;
        discriminator: string;
        global_name?: string;
        verified?: boolean;
        email?: string;
    }>();
    if (!meResult.verified) {
        throw new Error("email unverified");
    }

    const guildsResponse = await fetch(`${DISCORD_API_ROOT}/users/@me/guilds`, {
        headers: {
            Authorization: `Bearer ${accessToken}`,
        },
    });
    if (!guildsResponse.ok) {
        console.log(guildsResponse.status);
        console.log(await guildsResponse.text());
        throw new Error("failed to get guilds info");
    }
    const guilds = (await guildsResponse.json<{ id: string }[]>()).map(
        ({ id }) => id,
    );

    return {
        ...meResult,
        joinedGuildIds: guilds,
    };
};

export const rolesOf =
    (botToken: string) =>
    async (guildId: string, userId: string): Promise<string[]> => {
        const memberResponse = await fetch(
            `${DISCORD_API_ROOT}/guilds/${guildId}/members/${userId}`,
            {
                headers: {
                    Authorization: `Bot ${botToken}`,
                },
            },
        );
        const { roles } = await memberResponse.json<{
            roles: string[];
        }>();
        return roles;
    };
