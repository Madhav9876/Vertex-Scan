import React, { createContext, useContext, useEffect } from 'react';

const ThemeContext = createContext(null);

const STORAGE_KEY = 'vertexscan-theme';

const THEME = 'dark';

export function ThemeProvider({ children }) {
  useEffect(() => {
    const root = document.documentElement;
    root.classList.add('dark');
    root.style.colorScheme = 'dark';
    localStorage.setItem(STORAGE_KEY, THEME);
  }, []);

  return (
    <ThemeContext.Provider value={{ theme: THEME, resolved: THEME }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useTheme must be used within ThemeProvider');
  return ctx;
}
