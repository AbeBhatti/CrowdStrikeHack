const DASH_RE = /[\u2014\u2013]|--/g;
const EMOJI_RE = /[\u{1F300}-\u{1FAFF}]/gu;

export function forbiddenInText(text: string): boolean {
  DASH_RE.lastIndex = 0;
  EMOJI_RE.lastIndex = 0;
  return DASH_RE.test(text) || EMOJI_RE.test(text);
}

export function stripForbidden(text: string): string {
  return text.replace(DASH_RE, " ").replace(EMOJI_RE, "").replace(/\s+/g, " ").trim();
}
