import { useEffect, useState } from 'react';
import { useDeviceProfile } from './useDeviceProfile';
import { useReducedMotion } from './useReducedMotion';

/**
 * Central decision point for whether expensive decorative animations
 * (WebGL shaders, continuous canvas redraws) should run at all.
 *
 * - Respects prefers-reduced-motion.
 * - Gates based on device tier (mobile/low-power -> static fallback).
 * - Pauses automatically when the tab is hidden.
 *
 * `quality` is a normalized 0..1 multiplier that animation components can use
 * to scale DPR / sample counts / speed for a smoother experience.
 */
export function useAnimationBudget() {
  const device = useDeviceProfile();
  const reduced = useReducedMotion();

  const [hidden, setHidden] = useState(
    typeof document !== 'undefined' ? document.hidden : false
  );

  useEffect(() => {
    const onChange = () => setHidden(document.hidden);
    document.addEventListener('visibilitychange', onChange);
    return () => document.removeEventListener('visibilitychange', onChange);
  }, []);

  let quality = 1;
  if (device.isMobile) quality = 0.5;
  else if (device.isTablet) quality = 0.75;
  if (device.lowPower) quality = Math.min(quality, 0.4);

  const animationAllowed = !reduced && !hidden;

  // Per-component allowance based on how heavy each effect is.
  return {
    reduced,
    hidden,
    device,
    quality,
    // Full-screen WebGL shader background (heavy)
    allowBackgroundShader: animationAllowed && device.tier !== 'low',
    // Interactive shader / canvas border (medium-heavy)
    allowCanvasFx: animationAllowed && !device.lowPower,
    // Lightweight CSS/GSAP motion (cheap)
    allowUiMotion: animationAllowed
  };
}

export default useAnimationBudget;
