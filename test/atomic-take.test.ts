import { describe, expect, it } from "vitest";
import {
  atomicTakeIf,
  atomicUpdateIf,
  type AtomicStorage,
  type AtomicTransaction,
} from "../src/storage/atomic-take";

class FakeAtomicStorage implements AtomicStorage, AtomicTransaction {
  readonly values = new Map<string, unknown>();
  private tail = Promise.resolve();

  transaction<T>(
    callback: (transaction: AtomicTransaction) => Promise<T>,
  ): Promise<T> {
    const previous = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    return previous.then(async () => {
      try {
        return await callback(this);
      } finally {
        release();
      }
    });
  }

  get<T>(key: string): Promise<T | undefined> {
    return Promise.resolve(this.values.get(key) as T | undefined);
  }

  delete(key: string): Promise<boolean> {
    return Promise.resolve(this.values.delete(key));
  }

  put<T>(key: string, value: T): Promise<void> {
    this.values.set(key, value);
    return Promise.resolve();
  }
}

describe("atomic storage consumption", () => {
  it("allows only one concurrent accepted consumer", async () => {
    const storage = new FakeAtomicStorage();
    storage.values.set("preparation", { approved: true });
    const outcomes = await Promise.all([
      atomicTakeIf<{ approved: boolean }>(
        storage,
        "preparation",
        (value) => value.approved,
      ),
      atomicTakeIf<{ approved: boolean }>(
        storage,
        "preparation",
        (value) => value.approved,
      ),
    ]);
    expect(outcomes.filter((value) => value !== undefined)).toHaveLength(1);
  });

  it("does not consume a value rejected by the predicate", async () => {
    const storage = new FakeAtomicStorage();
    storage.values.set("preparation", { digest: "expected" });
    await expect(
      atomicTakeIf<{ digest: string }>(
        storage,
        "preparation",
        (value) => value.digest === "wrong",
      ),
    ).resolves.toBeUndefined();
    expect(storage.values.has("preparation")).toBe(true);
  });

  it("updates a value without racing an atomic consumer", async () => {
    const storage = new FakeAtomicStorage();
    storage.values.set("preparation", { approved: false });
    await atomicUpdateIf<{ approved: boolean }>(
      storage,
      "preparation",
      (value) => ({ ...value, approved: true }),
    );
    const outcomes = await Promise.all([
      atomicTakeIf<{ approved: boolean }>(
        storage,
        "preparation",
        (value) => value.approved,
      ),
      atomicTakeIf<{ approved: boolean }>(
        storage,
        "preparation",
        (value) => value.approved,
      ),
    ]);
    expect(outcomes.filter((value) => value !== undefined)).toHaveLength(1);
    expect(storage.values.has("preparation")).toBe(false);
  });
});
