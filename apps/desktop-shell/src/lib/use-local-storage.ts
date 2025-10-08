import { useCallback, useEffect, useState } from 'react';

export function useLocalStorage<T>(key: string, defaultValue: T) {
  const [storedValue, setStoredValue] = useState<T>(() => {
    if (typeof window === 'undefined') {
      return defaultValue;
    }

    try {
      const item = window.localStorage.getItem(key);
      if (item === null) {
        return defaultValue;
      }
      return JSON.parse(item) as T;
    } catch (error) {
      console.warn('Failed to read localStorage', error);
      return defaultValue;
    }
  });

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }

    try {
      window.localStorage.setItem(key, JSON.stringify(storedValue));
    } catch (error) {
      console.warn('Failed to write localStorage', error);
    }
  }, [key, storedValue]);

  const setValue = useCallback((value: T | ((previous: T) => T)) => {
    setStoredValue((previous) => {
      return value instanceof Function ? value(previous) : value;
    });
  }, []);

  return [storedValue, setValue] as const;
}
