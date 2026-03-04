export function calculateEntropy(str) {
  const map = {};
  for (const char of str) {
    map[char] = (map[char] || 0) + 1;
  }

  const len = str.length;
  let entropy = 0;

  for (const char in map) {
    const p = map[char] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}