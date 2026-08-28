import { describe, it, expect } from "vitest";
import {
  Claims,
  DebugState,
  IntendedUse,
  issue,
  verify,
  signer,
  peek,
} from "../src/cwt.js";
import { SecretKey as XdsaSecretKey } from "../src/xdsa.js";
import { SecretKey as XhpkeSecretKey } from "../src/xhpke.js";

describe("cwt", () => {
  function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  describe("issue/verify", () => {
    it("issues and verifies a basic token", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const deviceKey = await XdsaSecretKey.generate();
      const devicePub = await deviceKey.publicKey();
      const domain = new TextEncoder().encode("test-domain");

      const claims = new Claims();
      claims.subject = "device-abc";
      claims.notBefore = 1000000;
      claims.expiration = 2000000;
      claims.setConfirmXdsa(devicePub);

      const token = await issue(claims, issuerKey, domain);
      expect(token.length).toBeGreaterThan(0);

      const verified = await verify(token, issuerPub, domain, 1500000);
      expect(verified.subject).toBe("device-abc");
      expect(verified.notBefore).toBe(1000000);
      expect(verified.expiration).toBe(2000000);
    });

    it("accepts a fractional now timestamp", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const domain = new TextEncoder().encode("test-domain");

      const claims = new Claims();
      claims.notBefore = 1000000;
      claims.expiration = 2000000;

      const token = await issue(claims, issuerKey, domain);
      const verified = await verify(token, issuerPub, domain, 1500000.5);
      expect(verified.notBefore).toBe(1000000);

      await expect(verify(token, issuerPub, domain, -1)).rejects.toThrow();
    });

    it("roundtrips all standard CWT claims", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.issuer = "test-issuer";
      claims.subject = "test-subject";
      claims.audience = "test-audience";
      claims.expiration = 9999999;
      claims.notBefore = 1000000;
      claims.issuedAt = 1500000;
      claims.tokenId = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

      const token = await issue(claims, issuerKey, domain);
      const verified = await verify(token, issuerPub, domain, 1500000);

      expect(verified.issuer).toBe("test-issuer");
      expect(verified.subject).toBe("test-subject");
      expect(verified.audience).toBe("test-audience");
      expect(verified.expiration).toBe(9999999);
      expect(verified.notBefore).toBe(1000000);
      expect(verified.issuedAt).toBe(1500000);
      expect(toHex(verified.tokenId!)).toBe("deadbeef");
    });

    it("skips temporal validation when now is undefined", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "test";
      claims.notBefore = 1000000;

      const token = await issue(claims, issuerKey, domain);
      // Should succeed without temporal check even though no exp
      const verified = await verify(token, issuerPub, domain);
      expect(verified.subject).toBe("test");
    });

    it("validates now == nbf passes (boundary)", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "boundary";
      claims.notBefore = 1000000;
      claims.expiration = 2000000;

      const token = await issue(claims, issuerKey, domain);
      // now == nbf should pass
      const verified = await verify(token, issuerPub, domain, 1000000);
      expect(verified.subject).toBe("boundary");
    });

    it("validates now == exp fails (boundary)", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "boundary";
      claims.notBefore = 1000000;
      claims.expiration = 2000000;

      const token = await issue(claims, issuerKey, domain);
      // now == exp should fail
      await expect(verify(token, issuerPub, domain, 2000000)).rejects.toThrow();
    });

    it("rejects token before nbf", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "test";
      claims.notBefore = 1000000;

      const token = await issue(claims, issuerKey, domain);
      await expect(verify(token, issuerPub, domain, 500000)).rejects.toThrow();
    });

    it("rejects expired token", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "test";
      claims.notBefore = 1000000;
      claims.expiration = 2000000;

      const token = await issue(claims, issuerKey, domain);
      await expect(verify(token, issuerPub, domain, 3000000)).rejects.toThrow();
    });

    it("rejects token with wrong verifier", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const wrongKey = await XdsaSecretKey.generate();
      const wrongPub = await wrongKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "test";
      claims.notBefore = 1000000;

      const token = await issue(claims, issuerKey, domain);
      await expect(verify(token, wrongPub, domain, 1500000)).rejects.toThrow();
    });

    it("rejects token with wrong domain", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();

      const claims = new Claims();
      claims.subject = "test";
      claims.notBefore = 1000000;

      const token = await issue(
        claims,
        issuerKey,
        new TextEncoder().encode("domain-a"),
      );
      await expect(
        verify(token, issuerPub, new TextEncoder().encode("domain-b"), 1500000),
      ).rejects.toThrow();
    });

    it("passes without expiration when time check is on", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "no-exp";
      claims.notBefore = 1000000;
      // No expiration set

      const token = await issue(claims, issuerKey, domain);
      // Should pass even far in the future
      const verified = await verify(token, issuerPub, domain, 99999999);
      expect(verified.subject).toBe("no-exp");
    });
  });

  describe("confirm key binding", () => {
    it("roundtrips xDSA confirm key", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const deviceKey = await XdsaSecretKey.generate();
      const devicePub = await deviceKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "device";
      claims.notBefore = 1000000;
      claims.setConfirmXdsa(devicePub);

      const token = await issue(claims, issuerKey, domain);
      const verified = await verify(token, issuerPub, domain, 1500000);

      const recovered = await verified.getConfirmXdsa();
      expect(recovered).toBeDefined();
      expect(toHex(recovered!.toBytes())).toBe(toHex(devicePub.toBytes()));

      // Should not be found as xHPKE
      expect(await verified.getConfirmXhpke()).toBeUndefined();
    });

    it("roundtrips xHPKE confirm key", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const encKey = await XhpkeSecretKey.generate();
      const encPub = await encKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "device";
      claims.notBefore = 1000000;
      claims.setConfirmXhpke(encPub);

      const token = await issue(claims, issuerKey, domain);
      const verified = await verify(token, issuerPub, domain, 1500000);

      const recovered = await verified.getConfirmXhpke();
      expect(recovered).toBeDefined();
      expect(toHex(recovered!.toBytes())).toBe(toHex(encPub.toBytes()));

      // Should not be found as xDSA
      expect(await verified.getConfirmXdsa()).toBeUndefined();
    });
  });

  describe("signer/peek", () => {
    it("extracts signer fingerprint", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "test";
      claims.notBefore = 1000000;

      const token = await issue(claims, issuerKey, domain);
      const fp = await signer(token);

      expect(fp.toBytes().length).toBe(32);

      // Should match the issuer's fingerprint
      const issuerFp = await issuerKey.fingerprint();
      expect(toHex(fp.toBytes())).toBe(toHex(issuerFp.toBytes()));
    });

    it("peeks at unverified claims", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "peek-test";
      claims.notBefore = 1000000;
      claims.expiration = 2000000;

      const token = await issue(claims, issuerKey, domain);
      const peeked = await peek(token);

      expect(peeked.subject).toBe("peek-test");
      expect(peeked.notBefore).toBe(1000000);
      expect(peeked.expiration).toBe(2000000);
    });
  });

  describe("EAT claims", () => {
    it("roundtrips UEID", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "device";
      claims.notBefore = 1000000;
      claims.ueid = new Uint8Array([0x01, 0x02, 0x03, 0x04]);

      const token = await issue(claims, issuerKey, domain);
      const verified = await verify(token, issuerPub, domain, 1500000);

      expect(toHex(verified.ueid!)).toBe("01020304");
    });

    it("roundtrips OEMID random", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "device";
      claims.notBefore = 1000000;
      const oemidBytes = new Uint8Array(16);
      oemidBytes.fill(0xab);
      claims.setOemidRandom(oemidBytes);

      const token = await issue(claims, issuerKey, domain);
      const verified = await verify(token, issuerPub, domain, 1500000);

      const recovered = verified.oemid as Uint8Array;
      expect(recovered.length).toBe(16);
      expect(toHex(recovered)).toBe("ab".repeat(16));
    });

    it("roundtrips OEMID PEN", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "device";
      claims.notBefore = 1000000;
      claims.setOemidPen(12345);

      const token = await issue(claims, issuerKey, domain);
      const verified = await verify(token, issuerPub, domain, 1500000);

      expect(verified.oemid).toBe(12345);
    });

    it("validates OEMID random length", () => {
      const claims = new Claims();
      expect(() => claims.setOemidRandom(new Uint8Array(15))).toThrow();
      expect(() => claims.setOemidRandom(new Uint8Array(17))).toThrow();
    });

    it("validates OEMID IEEE length", () => {
      const claims = new Claims();
      expect(() => claims.setOemidIeee(new Uint8Array(2))).toThrow();
      expect(() => claims.setOemidIeee(new Uint8Array(4))).toThrow();
    });

    it("roundtrips hw/sw version", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "device";
      claims.notBefore = 1000000;
      claims.hwVersion = "1.2.3";
      claims.swVersion = "4.5.6";
      claims.hwModel = new Uint8Array([0x01, 0x02]);

      const token = await issue(claims, issuerKey, domain);
      const verified = await verify(token, issuerPub, domain, 1500000);

      expect(verified.hwVersion).toBe("1.2.3");
      expect(verified.swVersion).toBe("4.5.6");
      expect(toHex(verified.hwModel!)).toBe("0102");
    });

    it("roundtrips debug state", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "device";
      claims.notBefore = 1000000;
      claims.debugStatus = DebugState.DisabledPermanently;

      const token = await issue(claims, issuerKey, domain);
      const verified = await verify(token, issuerPub, domain, 1500000);

      expect(verified.debugStatus).toBe(DebugState.DisabledPermanently);
    });

    it("roundtrips intended use", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "device";
      claims.notBefore = 1000000;
      claims.intendedUse = IntendedUse.CertIssuance;

      const token = await issue(claims, issuerKey, domain);
      const verified = await verify(token, issuerPub, domain, 1500000);

      expect(verified.intendedUse).toBe(IntendedUse.CertIssuance);
    });

    it("roundtrips boot claims", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "device";
      claims.notBefore = 1000000;
      claims.uptime = 3600;
      claims.oemBoot = true;
      claims.bootCount = 42;
      claims.bootSeed = new Uint8Array([0xca, 0xfe]);
      claims.swName = "firmware-v2";

      const token = await issue(claims, issuerKey, domain);
      const verified = await verify(token, issuerPub, domain, 1500000);

      expect(verified.uptime).toBe(3600);
      expect(verified.oemBoot).toBe(true);
      expect(verified.bootCount).toBe(42);
      expect(toHex(verified.bootSeed!)).toBe("cafe");
      expect(verified.swName).toBe("firmware-v2");
    });

    it("roundtrips a full EAT token", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const deviceKey = await XdsaSecretKey.generate();
      const devicePub = await deviceKey.publicKey();
      const domain = new TextEncoder().encode("device-attestation");

      const claims = new Claims();
      claims.issuer = "manufacturer";
      claims.subject = "device-001";
      claims.notBefore = 1000000;
      claims.expiration = 9000000;
      claims.setConfirmXdsa(devicePub);
      claims.ueid = new TextEncoder().encode("SN-999");
      claims.hwVersion = "2.0";
      claims.swVersion = "1.5.3";
      claims.swName = "secure-fw";
      claims.debugStatus = DebugState.DisabledFullyPermanently;
      claims.oemBoot = true;
      claims.intendedUse = IntendedUse.Registration;

      const token = await issue(claims, issuerKey, domain);
      const verified = await verify(token, issuerPub, domain, 1500000);

      expect(verified.issuer).toBe("manufacturer");
      expect(verified.subject).toBe("device-001");
      expect(verified.notBefore).toBe(1000000);
      expect(verified.expiration).toBe(9000000);
      expect(await verified.getConfirmXdsa()).toBeDefined();
      expect(toHex((await verified.getConfirmXdsa())!.toBytes())).toBe(
        toHex(devicePub.toBytes()),
      );
      expect(new TextDecoder().decode(verified.ueid!)).toBe("SN-999");
      expect(verified.hwVersion).toBe("2.0");
      expect(verified.swVersion).toBe("1.5.3");
      expect(verified.swName).toBe("secure-fw");
      expect(verified.debugStatus).toBe(DebugState.DisabledFullyPermanently);
      expect(verified.oemBoot).toBe(true);
      expect(verified.intendedUse).toBe(IntendedUse.Registration);
    });
  });

  describe("custom claims", () => {
    it("roundtrips custom integer-keyed claims", async () => {
      const issuerKey = await XdsaSecretKey.generate();
      const issuerPub = await issuerKey.publicKey();
      const domain = new TextEncoder().encode("test");

      const claims = new Claims();
      claims.subject = "test";
      claims.notBefore = 1000000;
      claims.set(1000, "custom-value");
      claims.set(1001, 42);

      const token = await issue(claims, issuerKey, domain);
      const verified = await verify(token, issuerPub, domain, 1500000);

      expect(verified.get(1000)).toBe("custom-value");
      expect(verified.get(1001)).toBe(42);
    });
  });
});
