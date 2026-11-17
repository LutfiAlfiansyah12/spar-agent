import * as crypto from 'node:crypto';

/**
 * HMAC-SHA256 over the RAW request body bytes — the same signed turn
 * contract the Agent Games platform uses for Proof Gatekeeper tasks.
 *
 * Header conventions accepted/produced (mirrors the platform agent's):
 *   - "sha256=<hex>"   (default when signing)
 *   - "v1=<hex>"
 *   - "<hex>"          (bare hex, verification only)
 *   - base64 variants
 */

export type SigStyle = 'sha256' | 'v1' | 'bare' | 'base64' | 'sha256-base64' | 'v1-base64';

const HEX64 = /^[0-9a-fA-F]{64}$/;
const B64 = /^[A-Za-z0-9+/]{43}=$/;

export const SIGNATURE_HEADER = 'x-agent-games-signature';

export function computeHmac(rawBody: Buffer, secret: string): Buffer {
  return crypto.createHmac('sha256', secret).update(rawBody).digest();
}

export function encodeHeader(digest: Buffer, style: SigStyle = 'sha256'): string {
  const hex = digest.toString('hex');
  switch (style) {
    case 'sha256':
      return `sha256=${hex}`;
    case 'v1':
      return `v1=${hex}`;
    case 'base64':
      return digest.toString('base64');
    case 'sha256-base64':
      return `sha256=${digest.toString('base64')}`;
    case 'v1-base64':
      return `v1=${digest.toString('base64')}`;
    default:
      return hex;
  }
}
