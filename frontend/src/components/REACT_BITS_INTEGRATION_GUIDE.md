# React Bits Integration Guide — Vertex Scan

## Overview

This document provides a complete integration plan for four open-source components from **React Bits** into the Vertex Scan frontend. Each section covers: dependency installation, file placement, code review & optimization, advanced usage, and error handling.

---

## Table of Contents

1. [DecryptedText](#1-decryptedtext)
2. [Antigravity](#2-antigravity)
3. [MagicBento](#3-magicbento)
4. [DarkVeil](#4-darkveil)
5. [Dependency Installation Summary](#5-dependency-installation-summary)

---

## 1. DecryptedText

### Status: ✅ Already Installed
**File:** `frontend/src/components/DecryptedText.jsx`

### Dependencies
- `motion` — ✅ Already installed (`^12.42.2`)

### Code Review & Optimization

| Issue | Severity | Fix |
|-------|----------|-----|
| `getNextIndex` recreated every render inside `useEffect` | Medium | Move outside or use `useRef` |
| `currentIteration` resets to 0 on every render | High | Use `useRef` instead of local variable |
| `setRevealedIndices` called with updater function that has side effects (`setDisplayText` inside) | Medium | Separate state updates |
| No cleanup of `intervalRef` on unmount (only on completion) | High | Add unmount cleanup |
| `removeRandomIndices` mutates `arr` via `splice` inside a state updater | Low | Use immutable approach |
| No `ResizeObserver` or container dimension checks | Low | Not critical for text |

### Optimized Version (Key Changes)

```jsx
// Use useRef for iteration counter instead of local variable
const iterationRef = useRef(0);

// In the useEffect:
useEffect(() => {
  if (!isAnimating) return;
  iterationRef.current = 0; // Reset on start

  intervalRef.current = setInterval(() => {
    // ... animation logic using iterationRef.current++
  }, speed);

  return () => {
    clearInterval(intervalRef.current);
    intervalRef.current = null;
  };
}, [isAnimating, ...]);
```

### Advanced Usage — 3 Creative Use Cases

#### Use Case 1: "Matrix Code Rain" Hero Title
```jsx
<DecryptedText
  text="VERTEX SCAN"
  speed={30}
  maxIterations={15}
  sequential
  revealDirection="center"
  characters="01アイウエオカキクケコ"
  animateOn="view"
  className="text-4xl font-bold text-green-400"
  parentClassName="inline-block"
  encryptedClassName="text-green-700"
/>
```

#### Use Case 2: "Toggle Password Reveal" Pattern
```jsx
<DecryptedText
  text="s3cur3P@ssw0rd!"
  speed={80}
  maxIterations={20}
  animateOn="click"
  clickMode="toggle"
  characters="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+"
  className="font-mono text-lg"
  encryptedClassName="text-red-500"
/>
```

#### Use Case 3: "Sequential Loading" Status Indicator
```jsx
<DecryptedText
  text="System initialized successfully"
  speed={40}
  maxIterations={8}
  sequential
  revealDirection="start"
  animateOn="view"
  useOriginalCharsOnly
  className="text-emerald-300"
  encryptedClassName="text-gray-600"
/>
```

### Error Handling & Robustness

1. **Empty text**: Add guard at top of component:
   ```jsx
   if (!text) return null;
   ```

2. **Single character text**: The `computeOrder` and `getNextIndex` functions handle this correctly, but add a fast-path:
   ```jsx
   if (text.length <= 1) {
     return <span className={parentClassName}>{text}</span>;
   }
   ```

3. **Rapid hover spam**: The `isAnimating` guard in `triggerHoverDecrypt` prevents re-triggering, but add a debounce:
   ```jsx
   const hoverTimeoutRef = useRef(null);
   const triggerHoverDecrypt = useCallback(() => {
     if (isAnimating) return;
     if (hoverTimeoutRef.current) clearTimeout(hoverTimeoutRef.current);
     // ... existing logic
   }, [isAnimating, text]);
   ```

4. **Memory leak on unmount**: Ensure `intervalRef` is cleared:
   ```jsx
   useEffect(() => {
     return () => {
       if (intervalRef.current) {
         clearInterval(intervalRef.current);
         intervalRef.current = null;
       }
     };
   }, []);
   ```

---

## 2. Antigravity

### Status: ❌ Needs Installation
**Target File:** `frontend/src/components/Antigravity.jsx`

### Dependencies
- `three` — ✅ Already installed (`^0.170.0`)
- `@react-three/fiber` — ❌ **Needs installation**

### Installation
```bash
cd frontend && npm install @react-three/fiber @react-three/drei
```

### File Structure
```
frontend/src/components/
├── Antigravity.jsx        # Main component (Canvas wrapper)
└── AntigravityInner.jsx   # (optional) Inner 3D logic, or keep inline
```

### Code Review & Optimization

| Issue | Severity | Fix |
|-------|----------|-----|
| `viewport` dependency in `useMemo` for particles | **High** | `viewport` changes on resize, causing full particle re-creation |
| `dummy` Object3D recreated every render via `useMemo` | Low | Move to `useRef` |
| `lastMousePos` / `virtualMouse` as refs but no cleanup | Low | Add cleanup on unmount |
| `mesh.setMatrixAt` called per particle every frame | Medium | Acceptable for instanced meshes, but batch with `count` limit |
| No `pixelRatio` capping | Medium | Add `dpr={[1, 2]}` to Canvas |
| No `frameloop` control | Low | Add `frameloop="demand"` when not animating |
| `particleShape` conditional geometry recreates on re-render | Medium | Memoize geometry selection |

### Optimized Version (Key Changes)

```jsx
// 1. Cap DPR on Canvas
<Canvas camera={{ position: [0, 0, 50], fov: 35 }} dpr={[1, 2]}>

// 2. Use useRef for dummy instead of useMemo
const dummy = useRef(new THREE.Object3D()).current;

// 3. Memoize particles without viewport dependency
const particles = useMemo(() => {
  const temp = [];
  for (let i = 0; i < count; i++) {
    temp.push({
      t: Math.random() * 100,
      factor: 20 + Math.random() * 100,
      speed: 0.01 + Math.random() / 200,
      xFactor: -50 + Math.random() * 100,
      yFactor: -50 + Math.random() * 100,
      zFactor: -50 + Math.random() * 100,
      mx: (Math.random() - 0.5) * 100,
      my: (Math.random() - 0.5) * 100,
      mz: (Math.random() - 0.5) * 20,
      cx: 0, cy: 0, cz: 0,
      vx: 0, vy: 0, vz: 0,
      randomRadiusOffset: (Math.random() - 0.5) * 2,
    });
  }
  return temp;
}, [count]);

// 4. Memoize geometry
const geometry = useMemo(() => {
  switch (particleShape) {
    case 'sphere': return new THREE.SphereGeometry(0.2, 16, 16);
    case 'box': return new THREE.BoxGeometry(0.3, 0.3, 0.3);
    case 'tetrahedron': return new THREE.TetrahedronGeometry(0.3);
    default: return new THREE.CapsuleGeometry(0.1, 0.4, 4, 8);
  }
}, [particleShape]);
```

### Advanced Usage — 3 Creative Use Cases

#### Use Case 1: "Galaxy Swirl" Hero Background
```jsx
<Antigravity
  count={500}
  magnetRadius={15}
  ringRadius={12}
  waveSpeed={0.8}
  waveAmplitude={2}
  particleSize={1.2}
  lerpSpeed={0.03}
  color="#FF6B6B"
  autoAnimate={true}
  rotationSpeed={0.5}
  depthFactor={2}
  pulseSpeed={2}
  particleShape="sphere"
  fieldStrength={15}
/>
```

#### Use Case 2: "Data Particle Network" Dashboard Widget
```jsx
<Antigravity
  count={200}
  magnetRadius={8}
  ringRadius={5}
  waveSpeed={0.2}
  waveAmplitude={0.3}
  particleSize={0.8}
  lerpSpeed={0.08}
  color="#00D4FF"
  autoAnimate={true}
  rotationSpeed={0.1}
  depthFactor={0.5}
  pulseSpeed={1}
  particleShape="tetrahedron"
  fieldStrength={20}
/>
```

#### Use Case 3: "Minimalist Loading" State
```jsx
<Antigravity
  count={100}
  magnetRadius={5}
  ringRadius={3}
  waveSpeed={0.1}
  waveAmplitude={0}
  particleSize={1.5}
  lerpSpeed={0.15}
  color="#A78BFA"
  autoAnimate={false}
  rotationSpeed={0}
  depthFactor={0.3}
  pulseSpeed={0}
  particleShape="capsule"
  fieldStrength={30}
/>
```

### Error Handling & Robustness

1. **Low-end devices**: Detect GPU tier and reduce count:
   ```jsx
   const [particleCount, setParticleCount] = useState(count);
   useEffect(() => {
     const gl = document.createElement('canvas').getContext('webgl');
     const debugInfo = gl?.getExtension('WEBGL_debug_renderer_info');
     const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : '';
     if (renderer && (renderer.includes('Intel HD') || renderer.includes('SwiftShader'))) {
       setParticleCount(Math.min(count, 100));
     }
   }, [count]);
   ```

2. **Mobile responsiveness**: Add `useMobileDetection`:
   ```jsx
   const isMobile = useMemo(() => window.innerWidth < 768, []);
   const effectiveCount = isMobile ? Math.min(count, 100) : count;
   ```

3. **Missing parent dimensions**: Add fallback container:
   ```jsx
   <div style={{ width: '100%', height: '400px', minHeight: '200px', position: 'relative' }}>
     <Antigravity count={effectiveCount} ... />
   </div>
   ```

4. **Canvas disposal on unmount**: The `Canvas` from R3F handles this automatically, but ensure no external refs leak.

---

## 3. MagicBento

### Status: ❌ Needs Installation
**Target File:** `frontend/src/components/MagicBento.jsx`
**Target CSS:** `frontend/src/components/MagicBento.css`

### Dependencies
- `gsap` — ❌ **Needs installation**

### Installation
```bash
cd frontend && npm install gsap
```

### File Structure
```
frontend/src/components/
├── MagicBento.jsx
└── MagicBento.css
```

### Code Review & Optimization

| Issue | Severity | Fix |
|-------|----------|-----|
| `ParticleCard` creates DOM elements directly (not React-managed) | **High** | Use React state + `useMemo` for particles, or keep DOM approach but add cleanup |
| `ref` callback in non-star card path creates new event listeners on every render | **High** | Use `useEffect` with proper cleanup instead of ref callback |
| `GlobalSpotlight` creates a DOM element appended to `document.body` | Medium | Use React portal or at least track for cleanup |
| `memoizedParticles` ref never resets when `particleCount` or `glowColor` changes | Medium | Add dependency tracking |
| `timeoutsRef` not fully cleared on unmount | Medium | Add unmount cleanup effect |
| `gsap.to()` called on every mousemove without throttling | **High** | Add RAF throttling for mousemove |
| `cardData` is hardcoded — not customizable via props | Low | Accept `cards` prop with fallback to default |
| `useMobileDetection` uses `useState` + `useEffect` — fine but could use `useMemo` with matchMedia | Low | Use `window.matchMedia` for better performance |

### Optimized Version (Key Changes)

```jsx
// 1. RAF-throttled mousemove handler
const rafRef = useRef(null);
const handleMouseMove = useCallback((e) => {
  if (rafRef.current) return;
  rafRef.current = requestAnimationFrame(() => {
    rafRef.current = null;
    // ... existing mousemove logic
  });
}, [enableTilt, enableMagnetism]);

// 2. Use matchMedia for mobile detection
const isMobile = useMemo(() => {
  if (typeof window === 'undefined') return false;
  return window.matchMedia('(max-width: 768px)').matches;
}, []);

// 3. Accept custom cardData via props
const MagicBento = ({
  cards = cardData, // Allow override
  // ... other props
}) => { ... };
```

### Advanced Usage — 3 Creative Use Cases

#### Use Case 1: "Cyberpunk Neon" Dashboard
```jsx
<MagicBento
  textAutoHide={true}
  enableStars={true}
  enableSpotlight={true}
  enableBorderGlow={true}
  enableTilt={true}
  enableMagnetism={true}
  clickEffect={true}
  spotlightRadius={400}
  particleCount={20}
  glowColor="0, 255, 255"
/>
```

#### Use Case 2: "Minimalist Dark Mode" Settings Panel
```jsx
<MagicBento
  textAutoHide={false}
  enableStars={false}
  enableSpotlight={false}
  enableBorderGlow={true}
  enableTilt={false}
  enableMagnetism={false}
  clickEffect={false}
  spotlightRadius={200}
  particleCount={0}
  glowColor="255, 255, 255"
/>
```

#### Use Case 3: "Gaming" Interactive Grid
```jsx
<MagicBento
  textAutoHide={true}
  enableStars={true}
  enableSpotlight={true}
  enableBorderGlow={true}
  enableTilt={true}
  enableMagnetism={true}
  clickEffect={true}
  spotlightRadius={500}
  particleCount={30}
  glowColor="255, 165, 0"
/>
```

### Error Handling & Robustness

1. **GSAP not loaded**: Add a check:
   ```jsx
   if (typeof gsap === 'undefined') {
     console.warn('GSAP not loaded. MagicBento animations disabled.');
     return <div className={className}>{children}</div>;
   }
   ```

2. **Missing parent dimensions**: Add `ResizeObserver` fallback:
   ```jsx
   useEffect(() => {
     if (!cardRef.current) return;
     const ro = new ResizeObserver(entries => {
       // Recalculate particle positions on resize
     });
     ro.observe(cardRef.current);
     return () => ro.disconnect();
   }, []);
   ```

3. **Touch devices**: The `mousemove` events don't fire on mobile. Add touch support:
   ```jsx
   const handleTouchMove = useCallback((e) => {
     const touch = e.touches[0];
     if (!touch) return;
     // Map touch to mouse-like coordinates
     const mouseEvent = { clientX: touch.clientX, clientY: touch.clientY };
     handleMouseMove(mouseEvent);
   }, [handleMouseMove]);
   ```

4. **Memory leak**: Ensure all DOM-created elements are cleaned up:
   ```jsx
   useEffect(() => {
     return () => {
       // Kill all GSAP animations
       gsap.killTweensOf(cardRef.current);
       // Remove any orphaned DOM elements
       document.querySelectorAll('.particle, .global-spotlight').forEach(el => el.remove());
     };
   }, []);
   ```

---

## 4. DarkVeil

### Status: ❌ Needs Installation
**Target File:** `frontend/src/components/DarkVeil.jsx`
**Target CSS:** `frontend/src/components/DarkVeil.css`

### Dependencies
- `ogl` — ❌ **Needs installation**

### Installation
```bash
cd frontend && npm install ogl
```

### File Structure
```
frontend/src/components/
├── DarkVeil.jsx
└── DarkVeil.css
```

### Code Review & Optimization

| Issue | Severity | Fix |
|-------|----------|-----|
| `uniforms` values updated every frame in `loop()` | **High** | Only update when prop values change — use refs to track |
| `resolutionScale` changes cause full effect recreation | Medium | Add `resolutionScale` to resize handler instead of full re-init |
| No `pixelRatio` capping (already uses `Math.min(dpr, 2)` — good) | ✅ Good | Keep as-is |
| `performance.now()` called every frame | Low | Use `state.clock.getElapsedTime()` pattern or just `Date.now()` |
| `hueShiftRGB` matrix multiplication every pixel | Medium | Acceptable for shader, but could be optimized with lookup textures |
| No `will-change` CSS hint on canvas | Low | Add via CSS |
| `parent.clientWidth/Height` could be 0 if parent is not visible | **High** | Add guard for zero dimensions |
| No `visibilitychange` handler to pause when tab is hidden | Medium | Add to save battery |

### Optimized Version (Key Changes)

```jsx
// 1. Guard against zero dimensions
const resize = () => {
  const w = parent.clientWidth;
  const h = parent.clientHeight;
  if (w === 0 || h === 0) return; // Skip if parent not visible
  renderer.setSize(w * resolutionScale, h * resolutionScale);
  program.uniforms.uResolution.value.set(w, h);
};

// 2. Pause when tab is hidden
const handleVisibilityChange = () => {
  if (document.hidden) {
    cancelAnimationFrame(frame);
    frame = 0;
  } else if (frame === 0) {
    loop();
  }
};
document.addEventListener('visibilitychange', handleVisibilityChange);

// 3. Use refs for uniform values to avoid re-creating the effect on every prop change
const uniformsRef = useRef({ hueShift, noiseIntensity, scanlineIntensity, speed, scanlineFrequency, warpAmount });
useEffect(() => {
  uniformsRef.current = { hueShift, noiseIntensity, scanlineIntensity, speed, scanlineFrequency, warpAmount };
}, [hueShift, noiseIntensity, scanlineIntensity, speed, scanlineFrequency, warpAmount]);
```

### Advanced Usage — 3 Creative Use Cases

#### Use Case 1: "Cyberpunk" Fullscreen Background
```jsx
<DarkVeil
  hueShift={180}
  noiseIntensity={0.15}
  scanlineIntensity={0.3}
  speed={0.8}
  scanlineFrequency={50}
  warpAmount={0.02}
  resolutionScale={1}
/>
```

#### Use Case 2: "VHS Glitch" Hero Section
```jsx
<DarkVeil
  hueShift={30}
  noiseIntensity={0.3}
  scanlineIntensity={0.5}
  speed={1.2}
  scanlineFrequency={80}
  warpAmount={0.05}
  resolutionScale={0.75}
/>
```

#### Use Case 3: "Subtle Ambient" Page Background
```jsx
<DarkVeil
  hueShift={0}
  noiseIntensity={0.05}
  scanlineIntensity={0.05}
  speed={0.3}
  scanlineFrequency={20}
  warpAmount={0.005}
  resolutionScale={0.5}
/>
```

### Error Handling & Robustness

1. **WebGL not supported**: Add fallback:
   ```jsx
   const [webglSupported, setWebglSupported] = useState(true);
   useEffect(() => {
     try {
       const testCanvas = document.createElement('canvas');
       const gl = testCanvas.getContext('webgl') || testCanvas.getContext('experimental-webgl');
       if (!gl) setWebglSupported(false);
     } catch {
       setWebglSupported(false);
     }
   }, []);
   if (!webglSupported) return <div className="darkveil-fallback" />;
   ```

2. **Parent container not visible**: Add `ResizeObserver` with dimension check:
   ```jsx
   const resizeObserver = useRef(null);
   useEffect(() => {
     resizeObserver.current = new ResizeObserver(entries => {
       for (const entry of entries) {
         const { width, height } = entry.contentRect;
         if (width > 0 && height > 0) resize();
       }
     });
     resizeObserver.current.observe(parent);
     return () => resizeObserver.current?.disconnect();
   }, []);
   ```

3. **Low-end device performance**: Reduce resolution:
   ```jsx
   const effectiveScale = useMemo(() => {
     if (typeof window === 'undefined') return resolutionScale;
     const memory = navigator.deviceMemory;
     if (memory && memory <= 4) return resolutionScale * 0.5;
     return resolutionScale;
   }, [resolutionScale]);
   ```

4. **Tab visibility**: Pause animation when tab is hidden:
   ```jsx
   useEffect(() => {
     const handleVisibility = () => {
       if (document.hidden) {
         cancelAnimationFrame(frame);
         frame = 0;
       } else if (frame === 0) {
         loop();
       }
     };
     document.addEventListener('visibilitychange', handleVisibility);
     return () => document.removeEventListener('visibilitychange', handleVisibility);
   }, []);
   ```

---

## 5. Dependency Installation Summary

Run these commands in order:

```bash
# Navigate to frontend directory
cd frontend

# Install all missing dependencies
npm install @react-three/fiber @react-three/drei gsap ogl

# Verify installation
npm ls @react-three/fiber @react-three/drei gsap ogl
```

### Dependency Table

| Component | Package | Status | Version to Install |
|-----------|---------|--------|-------------------|
| DecryptedText | `motion` | ✅ Already installed | ^12.42.2 |
| Antigravity | `three` | ✅ Already installed | ^0.170.0 |
| Antigravity | `@react-three/fiber` | ❌ Missing | latest |
| Antigravity | `@react-three/drei` | ❌ Missing (optional) | latest |
| MagicBento | `gsap` | ❌ Missing | latest |
| DarkVeil | `ogl` | ❌ Missing | latest |

### File Placement Summary

```
frontend/src/components/
├── DecryptedText.jsx    ✅ Already exists (reviewed, minor optimizations recommended)
├── Antigravity.jsx      ❌ Needs creation
├── MagicBento.jsx       ❌ Needs creation
├── MagicBento.css       ❌ Needs creation
├── DarkVeil.jsx         ❌ Needs creation
└── DarkVeil.css         ❌ Needs creation
```

### CSS Scoping Strategy

Since this project uses **TailwindCSS** with a global `index.css`, component-specific CSS should be:

1. **Scoped via unique class names** — All components already use unique BEM-like class names (`.darkveil-canvas`, `.magic-bento-card`, `.particle-container`, etc.)
2. **Imported per-component** — Each CSS file is imported at the top of its corresponding JSX file
3. **No CSS Modules needed** — The class names are specific enough to avoid conflicts
4. **Tailwind `@apply` not used** — The component CSS uses raw CSS, which is fine alongside Tailwind

**Important:** The `MagicBento.css` file contains `:root` variable declarations. To avoid global pollution, move these into the `.bento-section` scope:

```css
/* Instead of :root, scope to the component */
.bento-section {
  --hue: 27;
  --sat: 69%;
  --white: hsl(0, 0%, 100%);
  --purple-primary: rgba(132, 0, 255, 1);
  --purple-glow: rgba(132, 0, 255, 0.2);
  --purple-border: rgba(132, 0, 255, 0.8);
  --border-color: #2F293A;
  --background-dark: #120F17;
  color-scheme: light dark;
}
```

---

## Quick Start Checklist

- [ ] `cd frontend && npm install @react-three/fiber @react-three/drei gsap ogl`
- [ ] Copy `DarkVeil.jsx` → `frontend/src/components/DarkVeil.jsx`
- [ ] Copy `DarkVeil.css` → `frontend/src/components/DarkVeil.css`
- [ ] Copy `Antigravity.jsx` → `frontend/src/components/Antigravity.jsx`
- [ ] Copy `MagicBento.jsx` → `frontend/src/components/MagicBento.jsx`
- [ ] Copy `MagicBento.css` → `frontend/src/components/MagicBento.css`
- [ ] Update `MagicBento.css` to scope `:root` vars to `.bento-section`
- [ ] Apply minor optimizations to `DecryptedText.jsx` (iteration ref, unmount cleanup)
- [ ] Test each component in isolation before integrating into pages