import { en, type Messages } from "./en";
import { fr } from "./fr";

export type { Messages };
export type Locale = "en" | "fr";

const catalogs: Record<Locale, Messages> = { en, fr };

/** Default locale is English. Language switch can call setLocale later. */
let current: Locale = "en";

function syncDocumentLang(): void {
  if (typeof document !== "undefined") document.documentElement.lang = current;
}
syncDocumentLang();

export function t(): Messages {
  return catalogs[current];
}

export function setLocale(locale: Locale): void {
  current = locale;
  syncDocumentLang();
}

export function getLocale(): Locale {
  return current;
}
