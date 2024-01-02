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

export async function loadOrGenerateKeyPair(store: KVNamespace) {
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
