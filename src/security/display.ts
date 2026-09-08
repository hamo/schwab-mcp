const UNSAFE_DISPLAY_CHARACTER = /[\p{Cf}\u2028\u2029]/gu;

export function makeFormattingCharactersVisible(value: string): string {
  return value.replace(UNSAFE_DISPLAY_CHARACTER, (character) => {
    const codePoint = character.codePointAt(0);
    if (codePoint === undefined) throw new Error("Invalid display text");
    return codePoint <= 0xffff
      ? `\\u${codePoint.toString(16).padStart(4, "0")}`
      : `\\u{${codePoint.toString(16)}}`;
  });
}
