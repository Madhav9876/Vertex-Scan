export default function Logo({ size = 32 }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <linearGradient id="logoGrad" x1="0" y1="0" x2="100" y2="100">
          <stop offset="0%" stopColor="#818CF8" />
          <stop offset="50%" stopColor="#7C3AED" />
          <stop offset="100%" stopColor="#A855F7" />
        </linearGradient>
      </defs>
      {/* Shield body */}
      <path
        d="M50 6 L94 28 L94 68 C94 84 50 96 50 96 C50 96 6 84 6 68 L6 28 Z"
        fill="url(#logoGrad)"
        stroke="#C084FC"
        strokeWidth="2"
      />
      {/* Inner downward V */}
      <path
        d="M30 28 L50 68 L70 28"
        stroke="white"
        strokeWidth="9"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill="none"
      />
      {/* Bottom vertex dots */}
      <circle cx="6" cy="68" r="2.5" fill="white" />
      <circle cx="94" cy="68" r="2.5" fill="white" />
      <circle cx="50" cy="96" r="2.5" fill="white" />
    </svg>
  );
}