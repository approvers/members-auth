import type { KeyEntry, KeyStore } from "../key";

export class InMemoryKeyStore implements KeyStore {
    entry: KeyEntry | null = null;

    get(): Promise<KeyEntry | null> {
        return Promise.resolve(this.entry);
    }

    put(entry: KeyEntry): Promise<void> {
        this.entry = entry;
        return Promise.resolve();
    }
}
