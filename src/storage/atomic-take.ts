export interface AtomicTransaction {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
}

export function atomicUpdateIf<T>(
  storage: AtomicStorage,
  key: string,
  update: (value: T) => T | undefined | Promise<T | undefined>,
): Promise<T | undefined> {
  return storage.transaction(async (transaction) => {
    const value = await transaction.get<T>(key);
    if (value === undefined) return undefined;
    const updated = await update(value);
    if (updated === undefined) return undefined;
    await transaction.put(key, updated);
    return updated;
  });
}

export interface AtomicStorage {
  transaction<T>(
    callback: (transaction: AtomicTransaction) => Promise<T>,
  ): Promise<T>;
}

export function atomicTakeIf<T>(
  storage: AtomicStorage,
  key: string,
  accept: (value: T) => boolean | Promise<boolean>,
): Promise<T | undefined> {
  return storage.transaction(async (transaction) => {
    const value = await transaction.get<T>(key);
    if (value === undefined || !(await accept(value))) return undefined;
    await transaction.delete(key);
    return value;
  });
}
