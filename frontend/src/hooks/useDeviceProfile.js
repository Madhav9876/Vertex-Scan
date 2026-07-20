import { useEffect, useState } from 'react';

const getDeviceType = () => {
  if (typeof window === 'undefined') return 'desktop';
  const width = window.innerWidth;
  const coarse = window.matchMedia?.('(pointer: coarse)').matches;
  if (width < 640) return 'mobile';
  if (width < 1024 || coarse) return 'tablet';
  return 'desktop';
};

const detectCapabilities = () => {
  if (typeof window === 'undefined' || typeof navigator === 'undefined') {
    return { tier: 'desktop', isMobile: false, isTablet: false, isDesktop: true, cores: 4, lowPower: false };
  }

  const ua = navigator.userAgent || '';
  const width = window.innerWidth;
  const deviceType = getDeviceType();
  const isMobile = deviceType === 'mobile';
  const isTablet = deviceType === 'tablet';
  const isDesktop = deviceType === 'desktop';

  const cores = navigator.hardwareConcurrency || 4;
  const memory = navigator.deviceMemory || 4;

  const lowEndUA = /Android.*(Go|[\s])(?:[\d.]+)?|Windows Phone|Mobi|Mobile/i.test(ua);
  const lowPower = (isMobile && (cores <= 4 || memory <= 3)) || lowEndUA || (isMobile && width < 400);

  let tier = 'high';
  if (isMobile) tier = 'low';
  else if (isTablet) tier = 'medium';
  else tier = 'high';

  if (lowPower && tier === 'high') tier = 'medium';
  if (lowPower && tier === 'medium') tier = 'low';

  return { tier, isMobile, isTablet, isDesktop, cores, lowPower };
};

export function useDeviceProfile() {
  const [profile, setProfile] = useState(() => detectCapabilities());

  useEffect(() => {
    let raf;
    const onResize = () => {
      if (raf) cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => setProfile(detectCapabilities()));
    };
    window.addEventListener('resize', onResize);
    return () => {
      window.removeEventListener('resize', onResize);
      if (raf) cancelAnimationFrame(raf);
    };
  }, []);

  return profile;
}

export default useDeviceProfile;
