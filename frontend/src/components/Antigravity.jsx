/* eslint-disable react/no-unknown-property */
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { useMemo, useRef } from 'react';
import * as THREE from 'three';

/**
 * Inner component that runs inside the R3F Canvas.
 * All Antigravity-specific logic is isolated here.
 */
const AntigravityInner = ({
  count = 300,
  magnetRadius = 10,
  ringRadius = 10,
  waveSpeed = 0.4,
  waveAmplitude = 1,
  particleSize = 2,
  lerpSpeed = 0.1,
  color = '#22D3EE',
  autoAnimate = false,
  particleVariance = 1,
  rotationSpeed = 0,
  depthFactor = 1,
  pulseSpeed = 3,
  particleShape = 'capsule',
  fieldStrength = 10
}) => {
  const meshRef = useRef(null);
  const { viewport } = useThree();
  const dummy = useRef(new THREE.Object3D()).current;

  const lastMousePos = useRef({ x: 0, y: 0 });
  const lastMouseMoveTime = useRef(0);
  const virtualMouse = useRef({ x: 0, y: 0 });

  // Memoize particles WITHOUT viewport dependency to avoid re-creation on resize
  const particles = useMemo(() => {
    const temp = [];
    for (let i = 0; i < count; i++) {
      const t = Math.random() * 100;
      const speed = 0.01 + Math.random() / 200;

      temp.push({
        t,
        speed,
        mx: (Math.random() - 0.5) * 100,
        my: (Math.random() - 0.5) * 100,
        mz: (Math.random() - 0.5) * 20,
        cx: 0,
        cy: 0,
        cz: 0,
        vx: 0,
        vy: 0,
        vz: 0,
        randomRadiusOffset: (Math.random() - 0.5) * 2,
      });
    }
    return temp;
  }, [count]);

  // Memoize geometry to avoid recreation on every render
  const geometry = useMemo(() => {
    switch (particleShape) {
      case 'sphere':
        return new THREE.SphereGeometry(0.2, 16, 16);
      case 'box':
        return new THREE.BoxGeometry(0.3, 0.3, 0.3);
      case 'tetrahedron':
        return new THREE.TetrahedronGeometry(0.3);
      case 'capsule':
      default:
        return new THREE.CapsuleGeometry(0.1, 0.4, 4, 8);
    }
  }, [particleShape]);

  useFrame(state => {
    const mesh = meshRef.current;
    if (!mesh) return;

    const { viewport: v, pointer: m } = state;

    const mouseDist = Math.sqrt(
      Math.pow(m.x - lastMousePos.current.x, 2) + Math.pow(m.y - lastMousePos.current.y, 2)
    );

    if (mouseDist > 0.001) {
      lastMouseMoveTime.current = Date.now();
      lastMousePos.current = { x: m.x, y: m.y };
    }

    let destX = (m.x * v.width) / 2;
    let destY = (m.y * v.height) / 2;

    if (autoAnimate && Date.now() - lastMouseMoveTime.current > 2000) {
      const time = state.clock.getElapsedTime();
      destX = Math.sin(time * 0.5) * (v.width / 4);
      destY = Math.cos(time * 0.5 * 2) * (v.height / 4);
    }

    const smoothFactor = 0.05;
    virtualMouse.current.x += (destX - virtualMouse.current.x) * smoothFactor;
    virtualMouse.current.y += (destY - virtualMouse.current.y) * smoothFactor;

    const targetX = virtualMouse.current.x;
    const targetY = virtualMouse.current.y;

    const globalRotation = state.clock.getElapsedTime() * rotationSpeed;

    for (let i = 0; i < particles.length; i++) {
      const particle = particles[i];
      const { t: initialT, speed, mx, my, mz, randomRadiusOffset } = particle;

      particle.t += speed / 2;
      const currentT = particle.t;

      const projectionFactor = 1 - mz / 50;
      const projectedTargetX = targetX * projectionFactor;
      const projectedTargetY = targetY * projectionFactor;

      const dx = mx - projectedTargetX;
      const dy = my - projectedTargetY;
      const dist = Math.sqrt(dx * dx + dy * dy);

      let targetPos = { x: mx, y: my, z: mz * depthFactor };

      if (dist < magnetRadius) {
        const angle = Math.atan2(dy, dx) + globalRotation;

        const wave = Math.sin(currentT * waveSpeed + angle) * (0.5 * waveAmplitude);
        const deviation = randomRadiusOffset * (5 / (fieldStrength + 0.1));

        const currentRingRadius = ringRadius + wave + deviation;

        targetPos.x = projectedTargetX + currentRingRadius * Math.cos(angle);
        targetPos.y = projectedTargetY + currentRingRadius * Math.sin(angle);
        targetPos.z = mz * depthFactor + Math.sin(currentT) * (1 * waveAmplitude * depthFactor);
      }

      particle.cx += (targetPos.x - particle.cx) * lerpSpeed;
      particle.cy += (targetPos.y - particle.cy) * lerpSpeed;
      particle.cz += (targetPos.z - particle.cz) * lerpSpeed;

      dummy.position.set(particle.cx, particle.cy, particle.cz);

      dummy.lookAt(projectedTargetX, projectedTargetY, particle.cz);
      dummy.rotateX(Math.PI / 2);

      const currentDistToMouse = Math.sqrt(
        Math.pow(particle.cx - projectedTargetX, 2) + Math.pow(particle.cy - projectedTargetY, 2)
      );

      const distFromRing = Math.abs(currentDistToMouse - ringRadius);
      let scaleFactor = 1 - distFromRing / 10;

      scaleFactor = Math.max(0, Math.min(1, scaleFactor));

      const finalScale =
        scaleFactor * (0.8 + Math.sin(currentT * pulseSpeed) * 0.2 * particleVariance) * particleSize;
      dummy.scale.set(finalScale, finalScale, finalScale);

      dummy.updateMatrix();

      mesh.setMatrixAt(i, dummy.matrix);
    }

    mesh.instanceMatrix.needsUpdate = true;
  });

  return (
    <instancedMesh ref={meshRef} args={[undefined, undefined, count]}>
      <primitive object={geometry} attach="geometry" />
      <meshBasicMaterial color={color} />
    </instancedMesh>
  );
};

/**
 * Antigravity — A 3D particle ring that responds to mouse movement.
 *
 * @param {Object} props
 * @param {number} [props.count=300] - Number of particles
 * @param {number} [props.magnetRadius=10] - Radius of the magnetic field
 * @param {number} [props.ringRadius=10] - Radius of the formed ring
 * @param {number} [props.waveSpeed=0.4] - Speed of the wave animation
 * @param {number} [props.waveAmplitude=1] - Intensity of the wave (0 for perfect circle)
 * @param {number} [props.particleSize=2] - Scale multiplier for particles
 * @param {number} [props.lerpSpeed=0.1] - How fast particles move to the ring
 * @param {string} [props.color='#FF9FFC'] - Color of the particles
 * @param {boolean} [props.autoAnimate=false] - Automatically animate when idle
 * @param {number} [props.particleVariance=1] - Variance in particle size (0-1)
 * @param {number} [props.rotationSpeed=0] - Rotation speed of the ring
 * @param {number} [props.depthFactor=1] - Z-axis depth multiplier
 * @param {number} [props.pulseSpeed=3] - Speed of particle size pulsation
 * @param {string} [props.particleShape='capsule'] - Shape of the particles
 * @param {number} [props.fieldStrength=10] - Tightness of the ring formation
 */
const Antigravity = props => {
  return (
    <Canvas camera={{ position: [0, 0, 50], fov: 35 }} dpr={[1, 2]} gl={{ antialias: true, powerPreference: 'high-performance' }}>
      <AntigravityInner {...props} />
    </Canvas>
  );
};

export default Antigravity;