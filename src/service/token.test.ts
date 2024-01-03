import { Promise, Result } from "@mikuroxina/mini-fn";
import { expect, test } from "bun:test";

import { InMemoryKeyStore } from "../adaptor/in-memory";
import { loadOrGenerateKeyPair } from "./key";
import { type Token, token } from "./token";

test("happy path", async () => {
    const res = await token({
        code: "bar",
        generateToken: () =>
            Promise.pure(
                Result.ok({
                    access_token: "xxxx",
                    token_type: "Bearer",
                    expires_in: 604800,
                    refresh_token: "yyyy",
                    scope: "identify email",
                }),
            ),
        me: () =>
            Promise.pure({
                id: "0123456789",
                username: "TEST",
                discriminator: "0",
                verified: true,
                email: "test@example.com",
                joinedGuildIds: [],
            }),
        rolesOf: () => Promise.pure([]),
        getKeyPair: () => loadOrGenerateKeyPair(new InMemoryKeyStore()),
    });
    expect(Result.isOk(res)).toBeTrue();
    expect(
        (
            res[1] as {
                oAuthToken: Token;
                jwt: string;
            }
        ).oAuthToken,
    ).toStrictEqual({
        access_token: "xxxx",
        token_type: "Bearer",
        expires_in: 604800,
        refresh_token: "yyyy",
        scope: "identify email",
    });
});

test("unverified", async () => {
    const res = await token({
        code: "bar",
        generateToken: () =>
            Promise.pure(
                Result.ok({
                    access_token: "xxxx",
                    token_type: "Bearer",
                    expires_in: 604800,
                    refresh_token: "yyyy",
                    scope: "identify email",
                }),
            ),
        me: () =>
            Promise.pure({
                id: "0123456789",
                username: "TEST",
                discriminator: "0",
                joinedGuildIds: [],
            }),
        rolesOf: () => Promise.pure([]),
        getKeyPair: () => loadOrGenerateKeyPair(new InMemoryKeyStore()),
    });
    expect(Result.isErr(res)).toBeTrue();
    expect(res[1]).toStrictEqual("NOT_VERIFIED");
});

test("token failure", async () => {
    const res = await token({
        code: "bar",
        generateToken: () => Promise.pure(Result.err("TOKEN_GEN_FAILURE")),
        me: () =>
            Promise.pure({
                id: "0123456789",
                username: "TEST",
                discriminator: "0",
                joinedGuildIds: [],
            }),
        rolesOf: () => Promise.pure([]),
        getKeyPair: () => loadOrGenerateKeyPair(new InMemoryKeyStore()),
    });
    expect(Result.isErr(res)).toBeTrue();
    expect(res[1]).toStrictEqual("TOKEN_GEN_FAILURE");
});
