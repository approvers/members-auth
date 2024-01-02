import type { KeyEntry, KeyStore } from "../key";

const NAMESPACE_KEY = "keys";

export class KVKeyStore implements KeyStore {
    constructor(private readonly namespace: KVNamespace) {}

    get(): Promise<KeyEntry | null> {
        return this.namespace.get<KeyEntry>(NAMESPACE_KEY, { type: "json" });
    }

    async put(entry: KeyEntry): Promise<void> {
        await this.namespace.put(NAMESPACE_KEY, JSON.stringify(entry));
    }
}
