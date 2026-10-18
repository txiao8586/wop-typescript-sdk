import { describe, it, expect } from 'vitest';
import { parseSecurityReq } from '../src/suite';
import { WopError } from '../src/error';

describe('套件解析（F1，spec §2）', () => {
  it('WOP-RSA3072-SHA256 → 四维算法推导正确（§3.2）', () => {
    const s = parseSecurityReq('WOP-RSA3072-SHA256');
    expect(s.securityReq).toBe('WOP-RSA3072-SHA256');
    expect(s.keyAlgorithm).toBe('RSA');
    expect(s.keyLength).toBe(3072);
    expect(s.digestAlgorithm).toBe('SHA256');
    expect(s.signAlgorithm).toBe('SHA256withRSA');
    expect(s.messageAlgorithm).toBe('AES-256-GCM');
    expect(s.digestLabel).toBe('sha-256');
    expect(s.signatureB64uLength).toBe(512);
    expect(s.expectedDekAlg).toBe('AES-256-GCM');
  });

  it('WOP-RSA4096-SHA256 → 4096 位、签名恒 683 字符', () => {
    const s = parseSecurityReq('WOP-RSA4096-SHA256');
    expect(s.keyLength).toBe(4096);
    expect(s.signatureB64uLength).toBe(683);
    expect(s.keyWrapAlgorithm).toContain('4096');
  });

  it('WOP-SM2-SM3 → 抛"暂未支持"（Q7 裁决，消息精确）', () => {
    try {
      parseSecurityReq('WOP-SM2-SM3');
      expect.unreachable('应抛出 WopError');
    } catch (e) {
      expect(e).toBeInstanceOf(WopError);
      const err = e as WopError;
      expect(err.message).toBe('SM2-SM3 套件暂未支持，见 README 路线图');
      expect(err.category).toBe('unsupported');
    }
  });

  it('空值/空白 → 解析类明确拒绝', () => {
    for (const bad of ['', '   ', null as unknown as string, undefined as unknown as string]) {
      expect(() => parseSecurityReq(bad)).toThrowError(WopError);
      try {
        parseSecurityReq(bad);
      } catch (e) {
        expect((e as WopError).category).toBe('parse');
      }
    }
  });

  it('非三段式/前缀非 WOP → 解析类拒绝', () => {
    for (const bad of ['RSA3072-SHA256', 'WOP-RSA3072', 'WOP-RSA3072-SHA256-EXTRA', 'wop-rsa3072-sha256', 'WOP--SHA256', '-RSA3072-SHA256']) {
      try {
        parseSecurityReq(bad);
        expect.unreachable(`应拒绝：${bad}`);
      } catch (e) {
        expect(e).toBeInstanceOf(WopError);
        expect((e as WopError).category).toBe('parse');
        expect((e as WopError).message).toContain(bad === 'wop-rsa3072-sha256' ? 'WOP' : bad.trim() || '空');
      }
    }
  });

  it('算法不在支持列表 → 支持类明确拒绝', () => {
    for (const bad of ['WOP-RSA1024-SHA256', 'WOP-RSA3072-SHA384', 'WOP-SM4-SM3', 'WOP-ECDSA-SHA256']) {
      try {
        parseSecurityReq(bad);
        expect.unreachable(`应拒绝：${bad}`);
      } catch (e) {
        expect((e as WopError).category).toBe('unsupported');
        expect((e as WopError).message).toContain('不支持的算法');
      }
    }
  });

  it('WOP-RSA2048-SHA256：默认支持（crypto-spec E1 扩展位），定长 342 字符', () => {
    const suite = parseSecurityReq('WOP-RSA2048-SHA256');
    expect(suite.keyLength).toBe(2048);
    expect(suite.signatureB64uLength).toBe(342);
    expect(suite.digestLabel).toBe('sha-256');
    expect(suite.expectedDekAlg).toBe('AES-256-GCM');
    expect(parseSecurityReq('WOP-RSA2048-SHA256')).toBe(suite); // 缓存单例
  });

  it('跨族组合 → 支持类拒绝（I5，§2.3）', () => {
    for (const bad of ['WOP-RSA3072-SM3', 'WOP-SM2-SHA256']) {
      try {
        parseSecurityReq(bad);
        expect.unreachable(`应拒绝：${bad}`);
      } catch (e) {
        expect((e as WopError).category).toBe('unsupported');
        expect((e as WopError).message).toContain('跨族');
      }
    }
  });

  it('解析结果不可变（同一 securityReq 返回缓存单例，D7）', () => {
    const a = parseSecurityReq('WOP-RSA3072-SHA256');
    expect(parseSecurityReq('WOP-RSA3072-SHA256')).toBe(a);
    expect(Object.isFrozen(a)).toBe(true);
  });
});
