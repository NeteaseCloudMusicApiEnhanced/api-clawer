const crypto = require('./crypto');

describe('crypto', () => {
  describe('eapi encrypt/decrypt', () => {
    test('should encrypt and decrypt correctly', () => {
      const original = Buffer.from('Hello, World! This is a test message for eapi.');
      const encrypted = crypto.eapi.encrypt(original);
      const decrypted = crypto.eapi.decrypt(encrypted);
      expect(decrypted.toString()).toBe(original.toString());
    });

    test('should handle empty buffer', () => {
      const original = Buffer.from('');
      const encrypted = crypto.eapi.encrypt(original);
      const decrypted = crypto.eapi.decrypt(encrypted);
      expect(decrypted.toString()).toBe('');
    });
  });

  describe('linuxapi encrypt/decrypt', () => {
    test('should encrypt and decrypt correctly', () => {
      const original = Buffer.from('{"method":"POST","url":"https://music.163.com/api/test","params":{"id":1}}');
      const encrypted = crypto.linuxapi.encrypt(original);
      const decrypted = crypto.linuxapi.decrypt(encrypted);
      expect(decrypted.toString()).toBe(original.toString());
    });
  });

  describe('base64', () => {
    test('should encode and decode correctly', () => {
      const original = 'Hello World';
      const encoded = crypto.base64.encode(original);
      const decoded = crypto.base64.decode(encoded);
      expect(decoded).toBe(original);
    });

    test('should handle URL-safe characters', () => {
      const original = 'test+data/with=special?chars';
      const encoded = crypto.base64.encode(original);
      expect(encoded).not.toContain('+');
      expect(encoded).not.toContain('/');
      const decoded = crypto.base64.decode(encoded);
      expect(decoded).toBe(original);
    });
  });

  describe('md5', () => {
    test('should produce consistent hash', () => {
      const hash1 = crypto.md5.digest('test');
      const hash2 = crypto.md5.digest('test');
      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(32);
    });

    test('should produce different hash for different inputs', () => {
      const hash1 = crypto.md5.digest('hello');
      const hash2 = crypto.md5.digest('world');
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('random', () => {
    test('hex should produce correct length', () => {
      expect(crypto.random.hex(16)).toHaveLength(16);
      expect(crypto.random.hex(32)).toHaveLength(32);
    });

    test('uuid should produce valid format', () => {
      const uuid = crypto.random.uuid();
      expect(uuid).toMatch(/^[0-9a-f-]{36}$/);
    });
  });

  describe('eapi.encryptRequest', () => {
    test('should produce valid output', () => {
      const result = crypto.eapi.encryptRequest(
        'https://music.163.com/eapi/song/enhance/player/url',
        { id: '123', br: 320000 }
      );
      expect(result).toHaveProperty('url');
      expect(result).toHaveProperty('body');
      expect(result.body).toContain('params=');
    });
  });

  describe('linuxapi.encryptRequest', () => {
    test('should produce valid output', () => {
      const result = crypto.linuxapi.encryptRequest(
        'https://music.163.com/api/song/enhance/player/url',
        { id: '123' }
      );
      expect(result).toHaveProperty('url');
      expect(result).toHaveProperty('body');
      expect(result.url).toContain('/api/linux/forward');
    });
  });
});
