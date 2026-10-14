import { useEffect, useRef } from "react";

/**
 * Cursor-reactive grid for browsers without WebGL (GPU acceleration off or
 * blocked), so the stage never degrades to a static picture.
 *
 * Same idea as the cube field: a slow base wave plus a damped-spring surface
 * coupled to its neighbours (discrete wave equation). The cursor lifts the
 * surface and ripples travel outward. Drawn with plain 2D canvas lines.
 */

const NX = 29;
const NZ = 20;
const WORLD_W = 14;
const WORLD_D = 16;

const SIGMA = 2.2;          // cursor influence radius, in grid cells
const RAISE = 2.8;          // how far the cursor lifts the surface
const STIFFNESS = 40;
const DAMPING = 6.5;
const COUPLING = 22;

function rgb(hex) {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex.trim());
  const n = m ? parseInt(m[1], 16) : 0xa78bfa;

  return `${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}`;
}

function GridFallback({ pointer, running, interactive }) {
  const canvasRef = useRef(null);
  const live = useRef({ running, interactive });
  const surface = useRef(null);

  useEffect(() => {
    live.current = { running, interactive };
  }, [running, interactive]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext("2d");

    if (!ctx) return undefined;

    if (!surface.current) {
      surface.current = { d: new Float32Array(NX * NZ), v: new Float32Array(NX * NZ) };
    }

    const { d, v } = surface.current;
    let width = 0;
    let height = 0;
    let frame = 0;
    let last = performance.now();
    let t = 0;

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 1.5);

      width = canvas.clientWidth;
      height = canvas.clientHeight;
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const step = (dt) => {
      const p = pointer.current;
      const active = live.current.interactive && p.active;
      const pu = ((p.x + 1) / 2) * (NX - 1);
      const pv = ((p.y + 1) / 2) * (NZ - 1);           // screen up = far
      const push = 0.6 + Math.min(1, p.speed);

      for (let iz = 0; iz < NZ; iz += 1) {
        for (let ix = 0; ix < NX; ix += 1) {
          const i = iz * NX + ix;
          const target = active
            ? RAISE * push * Math.exp(-((ix - pu) ** 2 + (iz - pv) ** 2) / (2 * SIGMA * SIGMA))
            : 0;

          const around =
            d[iz * NX + Math.max(0, ix - 1)] + d[iz * NX + Math.min(NX - 1, ix + 1)] +
            d[Math.max(0, iz - 1) * NX + ix] + d[Math.min(NZ - 1, iz + 1) * NX + ix];

          v[i] += (STIFFNESS * (target - d[i]) - DAMPING * v[i] + COUPLING * (around - 4 * d[i])) * dt;
        }
      }

      for (let i = 0; i < d.length; i += 1) d[i] += v[i] * dt;

      p.speed *= 0.86;
    };

    const draw = () => {
      const ink = rgb(getComputedStyle(document.documentElement).getPropertyValue("--accent"));
      const f = height * 0.78;
      const horizon = height * 0.3;
      const cx = width / 2;

      ctx.clearRect(0, 0, width, height);

      const px = new Float32Array(NX * NZ);
      const py = new Float32Array(NX * NZ);

      for (let iz = 0; iz < NZ; iz += 1) {
        for (let ix = 0; ix < NX; ix += 1) {
          const i = iz * NX + ix;
          const x = (ix / (NX - 1) - 0.5) * WORLD_W;
          const z = (iz / (NZ - 1)) * WORLD_D;
          const lift = d[i] + 0.28 * Math.sin(t * 0.8 + ix * 0.35 + iz * 0.28);
          const s = f / (z + 3);

          px[i] = cx + x * s;
          py[i] = horizon + (3 - lift) * s;
        }
      }

      // rows (brighter and thicker where the surface is lifted)
      for (let iz = 0; iz < NZ; iz += 1) {
        const depth = (1 - iz / NZ) ** 1.4;

        for (let ix = 0; ix < NX - 1; ix += 1) {
          const i = iz * NX + ix;
          const energy = Math.min(1, Math.abs(d[i]) * 0.55);

          ctx.strokeStyle = `rgba(${ink}, ${0.2 + 0.45 * depth + 0.6 * energy})`;
          ctx.lineWidth = 1.2 + energy * 2;
          ctx.beginPath();
          ctx.moveTo(px[i], py[i]);
          ctx.lineTo(px[i + 1], py[i + 1]);
          ctx.stroke();
        }
      }

      // columns
      ctx.strokeStyle = `rgba(${ink}, 0.26)`;
      ctx.lineWidth = 1;

      for (let ix = 0; ix < NX; ix += 1) {
        ctx.beginPath();
        ctx.moveTo(px[ix], py[ix]);

        for (let iz = 1; iz < NZ; iz += 1) ctx.lineTo(px[iz * NX + ix], py[iz * NX + ix]);

        ctx.stroke();
      }
    };

    const tick = (now) => {
      const dt = Math.min(1 / 30, (now - last) / 1000);

      last = now;
      t += dt;
      step(dt);
      draw();
      frame = requestAnimationFrame(tick);
    };

    resize();
    window.addEventListener("resize", resize);

    if (running) frame = requestAnimationFrame(tick);
    else draw();                                         // one still frame when paused / reduced motion

    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("resize", resize);
    };
  }, [running, pointer]);

  return <canvas ref={canvasRef} className="grid-2d" />;
}

export default GridFallback;
