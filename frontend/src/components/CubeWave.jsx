/* eslint-disable react-hooks/immutability -- the scene is mutated imperatively
   on every frame (three.js camera, instanced matrices, pointer state refs). */
import { useEffect, useMemo, useRef, useState } from "react";
import { Canvas, useThree } from "@react-three/fiber";
import * as THREE from "three";

/**
 * Cube field - the product's stage.
 *
 * One InstancedMesh (single draw call) of GRID x GRID cubes.
 *
 * Each cube has two layers of height:
 *   1. a slow radial base wave (always moving)
 *   2. a physical disturbance layer: every cube is a damped spring that is
 *      pulled toward a target set by the cursor, AND coupled to its four
 *      neighbours (discrete wave equation). Moving the cursor injects
 *      energy, so the surface rises under the pointer and ripples outward,
 *      then settles back to the base wave by itself.
 *
 * Pointer -> world: the pointer is turned into a ray and intersected with
 * the floor plane, so the disturbance follows the cursor in 3D, not in 2D
 * screen space. Touch works through the same pointer events.
 *
 * Costs: frames are driven manually, paused when the tab is hidden, and a
 * single still frame is drawn under prefers-reduced-motion. Without WebGL
 * the wrapper renders a CSS fallback.
 */

const GRID = 21;
const SPACING = 1.0;
const CUBE = 0.86;

const SIGMA = 2.1;          // cursor influence radius, in cubes
const RAISE = 1.5;          // how far the cursor lifts the surface
const STIFFNESS = 46;       // pull toward the cursor target
const DAMPING = 7.5;        // slightly under critical -> a soft overshoot
const COUPLING = 38;        // neighbour coupling = ripple propagation
const IMPULSE = 22;         // energy injected per unit pointer speed

const LOW = new THREE.Color("#241f38");
const HIGH = new THREE.Color("#9378ea");
const GLOW = new THREE.Color("#efe8ff");

const FLOOR = new THREE.Plane(new THREE.Vector3(0, 1, 0), 0);

function Cubes({ time, pointer, interactive, running }) {
  const mesh = useRef(null);
  const light = useRef(null);
  const { camera, size, invalidate } = useThree();

  const state = useMemo(() => {
    const count = GRID * GRID;

    return {
      count,
      offset: new Float32Array(count),
      velocity: new Float32Array(count),
      dummy: new THREE.Object3D(),
      color: new THREE.Color(),
      ray: new THREE.Raycaster(),
      hit: new THREE.Vector3(),
      ndc: new THREE.Vector2(),
      lightTarget: new THREE.Vector3(),
    };
  }, []);

  // Dev-only probe so automated tests can read the surface displacement.
  useEffect(() => {
    if (import.meta.env.DEV) {
      window.__ddCubeOffsets = state.offset;
    }
  }, [state]);

  // Keep the whole field in frame for any aspect ratio.
  useEffect(() => {
    const aspect = size.width / Math.max(1, size.height);
    const distance = aspect >= 1.5 ? 18.5 : Math.min(40, 18.5 * (1.5 / aspect) ** 0.66);

    // portrait screens: look further ahead so the field rides in the upper
    // half and the composer sits below it instead of covering it
    const ahead = 3.4 + 9 * Math.max(0, 1 - aspect);

    camera.position.set(0, distance * 0.47, distance);
    camera.lookAt(0, -0.2, ahead);
    camera.updateProjectionMatrix();
    invalidate();
  }, [camera, size, invalidate]);

  const step = (dt) => {
    const { offset, velocity, dummy, color, ray, hit, ndc } = state;
    const mid = (GRID - 1) / 2;
    const p = pointer.current;
    const t = time.current;

    // cursor on the floor plane
    let px = 0;
    let pz = 0;
    let hasHit = false;

    if (interactive && p.active) {
      ndc.set(p.x, p.y);
      ray.setFromCamera(ndc, camera);
      hasHit = Boolean(ray.ray.intersectPlane(FLOOR, hit));

      if (hasHit) {
        px = hit.x / SPACING + mid;
        pz = hit.z / SPACING + mid;
      }
    }

    const speed = hasHit ? p.speed : 0;
    p.speed *= 0.86; // pointer speed decays between move events

    let energy = 0;

    // wave equation + cursor spring (explicit integration)
    for (let x = 0; x < GRID; x += 1) {
      for (let z = 0; z < GRID; z += 1) {
        const i = x * GRID + z;
        const dx = x - px;
        const dz = z - pz;

        const force = hasHit ? Math.exp(-(dx * dx + dz * dz) / (2 * SIGMA * SIGMA)) : 0;
        const target = force * RAISE;

        const left = x > 0 ? offset[i - GRID] : offset[i];
        const right = x < GRID - 1 ? offset[i + GRID] : offset[i];
        const up = z > 0 ? offset[i - 1] : offset[i];
        const down = z < GRID - 1 ? offset[i + 1] : offset[i];

        const laplacian = left + right + up + down - 4 * offset[i];

        velocity[i] +=
          (STIFFNESS * (target - offset[i]) +
            COUPLING * laplacian -
            DAMPING * velocity[i] +
            IMPULSE * force * speed) *
          dt;

        offset[i] += velocity[i] * dt;
        energy += Math.abs(velocity[i]) + Math.abs(offset[i]);
      }
    }

    // render instances
    let i = 0;

    for (let x = 0; x < GRID; x += 1) {
      for (let z = 0; z < GRID; z += 1) {
        const dx = x - mid;
        const dz = z - mid;
        const dist = Math.sqrt(dx * dx + dz * dz);

        const wave = (Math.sin(dist * 0.62 - t * 0.9) + 1) / 2;
        const lift = Math.max(-0.2, offset[i]);
        const height = 0.3 + wave * 1.7 + lift;

        dummy.position.set(dx * SPACING, height / 2 - 1.1, dz * SPACING);
        dummy.scale.set(1, Math.max(0.12, height), 1);
        dummy.updateMatrix();

        mesh.current.setMatrixAt(i, dummy.matrix);

        const glow = Math.min(1, Math.abs(offset[i]) * 0.55 + (hasHit ? Math.exp(-((x - px) ** 2 + (z - pz) ** 2) / 6) * 0.35 : 0));

        mesh.current.setColorAt(
          i,
          color.copy(LOW).lerp(HIGH, wave * 0.95).lerp(GLOW, glow * 0.7)
        );

        i += 1;
      }
    }

    mesh.current.instanceMatrix.needsUpdate = true;
    mesh.current.instanceColor.needsUpdate = true;

    if (light.current) {
      const orbit = Math.cos(t * 0.35) * 6;
      const tx = hasHit ? (px - mid) * SPACING : orbit;
      const tz = hasHit ? (pz - mid) * SPACING : Math.sin(t * 0.35) * 6;

      state.lightTarget.set(tx, 3.4, tz);
      light.current.position.lerp(state.lightTarget, Math.min(1, dt * 6));
      light.current.intensity += ((hasHit ? 70 : 46) - light.current.intensity) * Math.min(1, dt * 4);
    }

    return energy;
  };

  // paint a first frame, and re-paint when the static (reduced-motion) frame changes
  useEffect(() => {
    step(0.016);
    invalidate();
  });

  // animation driver
  useEffect(() => {
    if (!running) return undefined;

    let frame;
    let last = performance.now();
    let quiet = 0;

    const tick = (now) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      const elapsed = now - last;

      // 60 fps while the surface is disturbed, 30 fps when it is calm
      if (elapsed >= (quiet > 40 ? 32 : 15)) {
        last = now;
        time.current += dt;

        const energy = step(dt);

        quiet = energy < 3 && !pointer.current.active ? quiet + 1 : 0;

        invalidate();
      }

      frame = requestAnimationFrame(tick);
    };

    frame = requestAnimationFrame(tick);

    return () => cancelAnimationFrame(frame);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running]);

  return (
    <>
      <ambientLight intensity={0.5} />
      <directionalLight position={[4, 10, 4]} intensity={1.5} color="#d9ccff" />
      <pointLight ref={light} intensity={46} distance={18} decay={1.6} color="#ffffff" />

      <instancedMesh ref={mesh} args={[undefined, undefined, GRID * GRID]}>
        <boxGeometry args={[CUBE, 1, CUBE]} />
        <meshStandardMaterial roughness={0.6} metalness={0.06} />
      </instancedMesh>
    </>
  );
}

function hasWebGL() {
  try {
    const canvas = document.createElement("canvas");

    return Boolean(
      window.WebGLRenderingContext &&
        (canvas.getContext("webgl2") || canvas.getContext("webgl"))
    );
  } catch {
    return false;
  }
}

function CubeWave({ mode = "home", paused = false, allowReduced = false }) {
  const wrapper = useRef(null);
  const time = useRef(3.1);
  const pointer = useRef({ x: 0, y: 0, active: false, speed: 0, lastX: 0, lastY: 0 });

  const [supported] = useState(hasWebGL);
  const [tabActive, setTabActive] = useState(!document.hidden);
  const [systemReduced, setReduced] = useState(
    () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false
  );

  // A visitor's explicit "play" overrides the system reduced-motion default.
  const reduced = systemReduced && !allowReduced;

  useEffect(() => {
    const media = window.matchMedia?.("(prefers-reduced-motion: reduce)");
    const onMedia = (event) => setReduced(event.matches);
    const onVisibility = () => setTabActive(!document.hidden);

    media?.addEventListener?.("change", onMedia);
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      media?.removeEventListener?.("change", onMedia);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, []);

  // Pointer tracking lives on window so the cursor affects the field even
  // while it is over UI that sits in front of it (the stage ignores events).
  useEffect(() => {
    if (reduced) return undefined;

    const p = pointer.current;

    const update = (event) => {
      const nx = (event.clientX / window.innerWidth) * 2 - 1;
      const ny = -(event.clientY / window.innerHeight) * 2 + 1;

      const dx = nx - p.lastX;
      const dy = ny - p.lastY;

      p.speed = Math.min(1.4, p.speed * 0.5 + Math.hypot(dx, dy) * 9);
      p.lastX = nx;
      p.lastY = ny;
      p.x = nx;
      p.y = ny;
      p.active = true;
    };

    const leave = () => {
      p.active = false;
    };

    window.addEventListener("pointermove", update, { passive: true });
    window.addEventListener("pointerdown", update, { passive: true });
    window.addEventListener("pointerup", leave);
    window.addEventListener("pointercancel", leave);
    document.documentElement.addEventListener("pointerleave", leave);

    return () => {
      window.removeEventListener("pointermove", update);
      window.removeEventListener("pointerdown", update);
      window.removeEventListener("pointerup", leave);
      window.removeEventListener("pointercancel", leave);
      document.documentElement.removeEventListener("pointerleave", leave);
    };
  }, [reduced]);

  const running = tabActive && !reduced && !paused;

  return (
    <div ref={wrapper} className="stage" data-mode={mode} aria-hidden="true">
      {supported ? (
        <Canvas
          frameloop="demand"
          dpr={[1, 1.75]}
          camera={{ position: [0, 7.5, 12], fov: 38, near: 0.1, far: 80 }}
          gl={{ antialias: true, alpha: true, powerPreference: "high-performance" }}
        >
          <Cubes time={time} pointer={pointer} interactive={!reduced && !paused} running={running} />
        </Canvas>
      ) : (
        <div className="stage-fallback" />
      )}
    </div>
  );
}

export default CubeWave;
