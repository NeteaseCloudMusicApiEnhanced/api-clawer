const { isHost, cookieToMap, mapToCookie } = require('./utilities');

describe('utilities', () => {
  describe('isHost', () => {
    test('should match host in URL', () => {
      expect(isHost('https://music.163.com/api/playlist', 'music.163.com')).toBe(true);
    });

    test('should not match different host', () => {
      expect(isHost('https://example.com/api', 'music.163.com')).toBe(false);
    });

    test('should match host in subdomain', () => {
      expect(isHost('https://interface.music.163.com/api', 'music.163.com')).toBe(true);
    });
  });

  describe('cookieToMap', () => {
    test('should parse cookie string to map', () => {
      const result = cookieToMap('key1=value1; key2=value2');
      expect(result).toEqual({ key1: 'value1', key2: 'value2' });
    });

    test('should handle empty string', () => {
      const result = cookieToMap('');
      expect(result).toEqual({});
    });

    test('should handle cookies without space around =', () => {
      const result = cookieToMap('key1=value1; key2=value2');
      expect(result).toEqual({ key1: 'value1', key2: 'value2' });
    });
  });

  describe('mapToCookie', () => {
    test('should convert map to cookie string', () => {
      const result = mapToCookie({ key1: 'value1', key2: 'value2' });
      expect(result).toBe('key1=value1; key2=value2');
    });

    test('should handle empty map', () => {
      const result = mapToCookie({});
      expect(result).toBe('');
    });
  });

  describe('cookieToMap <-> mapToCookie round trip', () => {
    test('should be reversible', () => {
      const original = { a: '1', b: '2', c: '3' };
      const cookieStr = mapToCookie(original);
      const parsed = cookieToMap(cookieStr);
      expect(parsed).toEqual(original);
    });
  });
});
