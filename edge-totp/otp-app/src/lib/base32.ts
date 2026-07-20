const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Decode(input: string): Uint8Array {
  const s = input.toUpperCase().replace(/=+$/, "").replace(/\s/g, "");
  const bytes = new Uint8Array(Math.floor((s.length * 5) / 8));
  let buf = 0;
  let bits = 0;
  let idx = 0;

  for (let i = 0; i < s.length; i++) {
    const val = ALPHABET.indexOf(s[i]);
    if (val === -1) throw new Error(`Invalid base32 character: ${s[i]}`);
    buf = (buf << 5) | val;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes[idx++] = (buf >> bits) & 0xff;
    }
  }

  return bytes.slice(0, idx);
}

export function base32Encode(input: Uint8Array): string {
  let out = "";
  let buf = 0;
  let bits = 0;

  for (let i = 0; i < input.length; i++) {
    buf = (buf << 8) | input[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(buf >> bits) & 31];
    }
  }

  if (bits > 0) {
    out += ALPHABET[(buf << (5 - bits)) & 31];
  }

  return out;
}
