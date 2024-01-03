import { Cat, Promise, Result } from "@mikuroxina/mini-fn";
import { SignJWT } from "jose";

export interface Token {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token: string;
    scope: string;
}

export interface User {
    id: string;
    username: string;
    discriminator: string;
    verified?: boolean;
    email?: string;
    joinedGuildIds: string[];
}

export interface TokenDeps {
    code: string;
    generateToken(code: string): Promise<TokenResult<Token>>;
    me(accessToken: string): Promise<User>;
    rolesOf(guildId: string, userId: string): Promise<string[]>;
    getKeyPair: () => Promise<CryptoKeyPair>;
}

export type TokenError = "TOKEN_GEN_FAILURE" | "NOT_VERIFIED";
export type TokenResult<T> = Result.Result<TokenError, T>;

const monad = Promise.monadT(Result.traversableMonad<TokenError>());
const lift = Promise.map(<T>(t: T) => Result.ok(t));

const DISCORD_CLIENT_ID = "1191642657731121272";
const DISCORD_CHECK_GUILD_ID = "683939861539192860";

export const token = (
    deps: TokenDeps,
): Promise<TokenResult<{ oAuthToken: Token; jwt: string }>> =>
    Cat.doT(monad)
        .addM("token", deps.generateToken(deps.code))
        .addMWith("me", ({ token }) => lift(deps.me(token.access_token)))
        .addMWith("_", ({ me }) =>
            me.verified === true
                ? Promise.pure(Result.ok([]))
                : Promise.pure(Result.err("NOT_VERIFIED")),
        )
        .addMWith(
            "roleClaims",
            async ({
                me,
            }): Promise<
                TokenResult<{ [key: `roles:${string}`]: string[] | undefined }>
            > =>
                Result.ok(
                    me.joinedGuildIds.includes(DISCORD_CHECK_GUILD_ID)
                        ? {
                              [`roles:${DISCORD_CHECK_GUILD_ID}`]:
                                  await deps.rolesOf(
                                      DISCORD_CHECK_GUILD_ID,
                                      me.id,
                                  ),
                          }
                        : {},
                ),
        )
        .addM("keyPair", lift(deps.getKeyPair()))
        .addMWith("jwt", ({ me, roleClaims, keyPair }) =>
            lift(
                new SignJWT({
                    iss: "https://cloudflare.com",
                    aud: DISCORD_CLIENT_ID,
                    ...me,
                    ...roleClaims,
                    guilds: me.joinedGuildIds,
                })
                    .setProtectedHeader({ alg: "RS256" })
                    .setExpirationTime("1h")
                    .setAudience(DISCORD_CLIENT_ID)
                    .sign(keyPair.privateKey),
            ),
        )
        .finish(({ token, jwt }) => ({ oAuthToken: token, jwt }));
