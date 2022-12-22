export interface NativeAuthCacheInterface {
  getValue(key: string): Promise<number | undefined>;

  setValue(key: string, value: number, ttl: number): Promise<void>;
}
