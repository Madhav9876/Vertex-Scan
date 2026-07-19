import React from 'react';
import { Moon } from 'lucide-react';

export default function ThemeToggle({ className = '' }) {
  return (
    <div
      className={`inline-flex items-center rounded-lg border border-gray-700 bg-gray-800 p-0.5 ${className}`}
      role="group"
      aria-label="Theme mode"
    >
      <span
        title="Dark mode"
        aria-pressed="true"
        className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-sm font-medium transition-colors bg-gray-700 text-primary-300 shadow-sm"
      >
        <Moon size={15} />
        <span className="hidden sm:inline">Dark</span>
      </span>
    </div>
  );
}
