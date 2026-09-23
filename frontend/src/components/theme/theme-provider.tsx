"use client";

import React, { createContext, useContext, useEffect, useState } from "react";

type Theme = "dark" | "light";

interface ThemeContextType {
  theme: Theme;
  setTheme: (theme: Theme) => void;
  toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextType>({
  theme: "dark",
  setTheme: () => {},
  toggleTheme: () => {},
});

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>("dark");

  useEffect(() => {
    try {
      const saved = localStorage.getItem("cybersentry_theme") as Theme | null;
      const initialTheme = saved === "light" ? "light" : "dark";
      setThemeState(initialTheme);
      applyTheme(initialTheme);
    } catch {
      applyTheme("dark");
    }
  }, []);

  function applyTheme(newTheme: Theme) {
    if (typeof document === "undefined") return;
    const root = document.documentElement;
    if (newTheme === "dark") {
      root.classList.add("dark");
      root.classList.remove("light");
      root.style.colorScheme = "dark";
    } else {
      root.classList.remove("dark");
      root.classList.add("light");
      root.style.colorScheme = "light";
    }
  }

  function setTheme(newTheme: Theme) {
    setThemeState(newTheme);
    try {
      localStorage.setItem("cybersentry_theme", newTheme);
    } catch {}
    applyTheme(newTheme);
  }

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
  }

  return (
    <ThemeContext.Provider value={{ theme, setTheme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  return useContext(ThemeContext);
}
