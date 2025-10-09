import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

const REDACTION_PATTERN = /\[REDACTED[^\]]*\]/i;

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function isRedactedValue(value: unknown): boolean {
  if (typeof value === 'string') {
    return REDACTION_PATTERN.test(value);
  }
  if (Array.isArray(value)) {
    return value.some((item) => isRedactedValue(item));
  }
  if (value && typeof value === 'object') {
    return Object.values(value as Record<string, unknown>).some((item) => isRedactedValue(item));
  }
  return false;
}
