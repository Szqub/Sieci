export interface ParsedAddressInput {
  addresses: string[];
  duplicates: number;
  ignored: number;
}

export function parseAddressInput(value: string): ParsedAddressInput {
  const seen = new Set<string>();
  const addresses: string[] = [];
  let duplicates = 0;
  let ignored = 0;

  for (const rawLine of value.split(/\r?\n/)) {
    const line = rawLine.replace(/\s+#.*$/, "").trim();
    if (!line || line.startsWith("#")) {
      if (rawLine.trim()) ignored += 1;
      continue;
    }
    for (const rawToken of line.split(/[;,\s]+/)) {
      const token = rawToken.trim();
      if (!token) continue;
      if (seen.has(token)) {
        duplicates += 1;
        continue;
      }
      seen.add(token);
      addresses.push(token);
    }
  }
  return { addresses, duplicates, ignored };
}

export function pluralize(count: number, forms: [string, string, string]): string {
  if (count === 1) return forms[0];
  const mod10 = count % 10;
  const mod100 = count % 100;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return forms[1];
  return forms[2];
}
