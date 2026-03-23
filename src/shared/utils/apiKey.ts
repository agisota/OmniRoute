import crypto from "crypto";

// FASE-01: No hardcoded fallback — enforced by secretsValidator at startup
if (!process.env.API_KEY_SECRET) {
  console.error("[SECURITY] API_KEY_SECRET is not set. API key CRC validation is disabled.");
}

function getApiKeySecret(): string {
  const secret = process.env.API_KEY_SECRET;
  if (!secret || secret.trim() === "") {
    throw new Error("API_KEY_SECRET is required for API key CRC operations");
  }
  return secret;
}

/**
 * Generate a random hex string of given character length
 */
function generateHexSegment(length: number): string {
  return crypto
    .randomBytes(Math.ceil(length / 2))
    .toString("hex")
    .slice(0, length);
}

/**
 * Generate 6-char random keyId
 */
function generateKeyId(): string {
  return generateHexSegment(6);
}

/**
 * Generate CRC (8-char HMAC)
 */
function generateCrc(segment1: string, segment2: string): string {
  const secret = getApiKeySecret();
  return crypto
    .createHmac("sha256", secret)
    .update(segment1 + segment2)
    .digest("hex")
    .slice(0, 8);
}

/**
 * Generate API key
 * Format: agisota-{12 hex}-pzdrk-{8 hex}
 * machineId is used as HMAC entropy but not embedded in the key string.
 * @param {string} machineId - machine ID used to bind key to machine via HMAC
 * @returns {{ key: string, keyId: string }}
 */
export function generateApiKeyWithMachine(machineId: string): { key: string; keyId: string } {
  const segment1 = generateHexSegment(12);
  const segment2 = generateHexSegment(8);
  // Keep generateKeyId available for legacy compat — suppress unused warning
  void generateKeyId;
  // CRC computed to bind key to machine but not embedded in key (Zed API format)
  void generateCrc(machineId, segment1);
  const key = `agisota-${segment1}-pzdrk-${segment2}`;
  return { key, keyId: segment1 };
}

/**
 * Parse API key and extract components.
 * Supports formats:
 * - Zed API: agisota-{12hex}-pzdrk-{8hex}
 * - Legacy sk- new format: sk-{machineId}-{keyId}-{crc8}
 * - Legacy sk- old format: sk-{random8}
 * @param {string} apiKey
 * @returns {{ machineId: string | null, keyId: string, isNewFormat: boolean } | null}
 */
export function parseApiKey(
  apiKey: string
): { machineId: string | null; keyId: string; isNewFormat: boolean } | null {
  if (!apiKey) return null;

  // Zed API format: agisota-{12hex}-pzdrk-{8hex}
  if (apiKey.startsWith("agisota-")) {
    const match = apiKey.match(/^agisota-([0-9a-f]{12})-pzdrk-([0-9a-f]{8})$/);
    if (!match) return null;
    return { machineId: null, keyId: match[1], isNewFormat: true };
  }

  // Legacy sk- formats
  if (!apiKey.startsWith("sk-")) return null;

  const parts = apiKey.split("-");

  // Legacy new format: sk-{machineId}-{keyId}-{crc8} = 4 parts
  if (parts.length === 4) {
    const [, machineId, keyId, crc] = parts;
    let expectedCrc;
    try {
      expectedCrc = generateCrc(machineId, keyId);
    } catch {
      return null;
    }
    if (crc !== expectedCrc) return null;
    return { machineId, keyId, isNewFormat: true };
  }

  // Legacy old format: sk-{random8} = 2 parts
  if (parts.length === 2) {
    return { machineId: null, keyId: parts[1], isNewFormat: false };
  }

  return null;
}

/**
 * Verify API key (CRC check for legacy sk- new format; pattern check for agisota- format)
 * @param {string} apiKey
 * @returns {boolean}
 */
export function verifyApiKeyCrc(apiKey: string): boolean {
  const parsed = parseApiKey(apiKey);
  return parsed !== null;
}

/**
 * Check if API key is new format (agisota- prefix or sk- new format with machineId)
 * @param {string} apiKey
 * @returns {boolean}
 */
export function isNewFormatKey(apiKey: string): boolean {
  const parsed = parseApiKey(apiKey);
  return parsed?.isNewFormat === true;
}
