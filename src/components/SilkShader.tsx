import { useEffect, useRef } from 'react';

type SilkVariant = 'light' | 'dark' | 'lime';

interface SilkShaderProps {
  variant?: SilkVariant;
  speed?: number;
  className?: string;
}

const VARIANT_INDEX: Record<SilkVariant, number> = {
  light: 0.0,
  dark: 1.0,
  lime: 2.0,
};

/**
 * Soft "silk" gradient: slow flowing folds of light lit by a lime glow.
 * Replaces the old ribbed-glass look with the smooth, editorial feel of the references.
 */
export function SilkShader({ variant = 'light', speed = 1, className = '' }: SilkShaderProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const gl = canvas.getContext('webgl', { antialias: true, alpha: true, premultipliedAlpha: false });
    if (!gl) return;

    const vsSource = `
      attribute vec2 position;
      void main() {
        gl_Position = vec4(position, 0.0, 1.0);
      }
    `;

    const fsSource = `
      precision highp float;
      uniform vec2 u_resolution;
      uniform float u_time;
      uniform float u_variant;

      // Slowly drifting folds of silk, built from stacked warped waves
      float silk(vec2 p, float t) {
        float w = sin(p.x * 1.7 + t * 0.7) * 0.30
                + sin(p.x * 3.3 - t * 0.45) * 0.14
                + sin(p.y * 2.1 + t * 0.35) * 0.18;

        float folds = sin((p.y * 5.5 + w * 4.2) + t * 0.5) * 0.5 + 0.5;
        folds = pow(folds, 1.8);

        float micro = sin((p.y * 13.0 + w * 9.0) - t * 0.8) * 0.5 + 0.5;
        return mix(folds, folds * micro, 0.22);
      }

      void main() {
        vec2 uv = gl_FragCoord.xy / u_resolution.xy;
        float ar = max(u_resolution.x / max(u_resolution.y, 1.0), 0.001);

        vec2 p = uv;
        p.x *= ar;

        float t = u_time * 0.35;
        float s = silk(p, t);

        // Big soft light source that makes the fabric glow
        vec2 lightPos = vec2(0.78 * ar, 0.72);
        float d = distance(p, lightPos);
        float glow = exp(-2.4 * d * d);
        float coreGlow = exp(-9.0 * d * d);

        vec3 deep, mid, bright, base;
        float strength;

        // Brand palette only: white #FFFFFF, green #36FE35, ink #16191A
        vec3 WHITE = vec3(1.000, 1.000, 1.000);
        vec3 GREEN = vec3(0.212, 0.996, 0.208);
        vec3 INK   = vec3(0.086, 0.098, 0.102);

        if (u_variant < 0.5) {
          // Light: white paper brushed with brand-green silk
          base    = WHITE;
          deep    = mix(WHITE, GREEN, 0.18);
          mid     = mix(WHITE, GREEN, 0.75);
          bright  = WHITE;
          strength = 0.78;
        } else if (u_variant < 1.5) {
          // Dark: ink fabric with a brand-green core
          base    = INK;
          deep    = mix(INK, GREEN, 0.10);
          mid     = mix(INK, GREEN, 0.70);
          bright  = mix(GREEN, WHITE, 0.45);
          strength = 1.0;
        } else {
          // Green: saturated card fill
          base    = GREEN;
          deep    = mix(GREEN, INK, 0.22);
          mid     = GREEN;
          bright  = mix(GREEN, WHITE, 0.65);
          strength = 0.9;
        }

        vec3 col = mix(deep, mid, smoothstep(0.15, 0.85, s));
        col = mix(col, bright, smoothstep(0.55, 1.0, s * (0.45 + glow)));

        // Fabric shading: valleys stay dark, crests catch the light
        col *= mix(0.72, 1.12, s);
        col += bright * coreGlow * 0.35;

        // Blend the silk onto the base colour, concentrated around the light
        float presence = clamp(strength * (0.30 + 0.85 * glow), 0.0, 1.0);
        vec3 finalColor = mix(base, col, presence);

        gl_FragColor = vec4(finalColor, 1.0);
      }
    `;

    const compileShader = (type: number, source: string) => {
      const shader = gl.createShader(type);
      if (!shader) return null;
      gl.shaderSource(shader, source);
      gl.compileShader(shader);
      if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
        console.error('Shader compile error:', gl.getShaderInfoLog(shader));
        gl.deleteShader(shader);
        return null;
      }
      return shader;
    };

    const vertexShader = compileShader(gl.VERTEX_SHADER, vsSource);
    const fragmentShader = compileShader(gl.FRAGMENT_SHADER, fsSource);
    if (!vertexShader || !fragmentShader) return;

    const program = gl.createProgram();
    if (!program) return;
    gl.attachShader(program, vertexShader);
    gl.attachShader(program, fragmentShader);
    gl.linkProgram(program);
    gl.useProgram(program);

    const positionBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]),
      gl.STATIC_DRAW,
    );

    const positionLocation = gl.getAttribLocation(program, 'position');
    gl.enableVertexAttribArray(positionLocation);
    gl.vertexAttribPointer(positionLocation, 2, gl.FLOAT, false, 0, 0);

    const timeLocation = gl.getUniformLocation(program, 'u_time');
    const resolutionLocation = gl.getUniformLocation(program, 'u_resolution');
    const variantLocation = gl.getUniformLocation(program, 'u_variant');
    gl.uniform1f(variantLocation, VARIANT_INDEX[variant]);

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.max(canvas.clientWidth * dpr, 1);
      canvas.height = Math.max(canvas.clientHeight * dpr, 1);
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.uniform2f(resolutionLocation, canvas.width, canvas.height);
    };

    window.addEventListener('resize', resize);
    resize();

    let animationFrameId = 0;
    const startTime = Date.now();
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const render = () => {
      const time = prefersReducedMotion ? 0 : (Date.now() - startTime) * 0.001 * speed;
      gl.uniform1f(timeLocation, time);
      gl.drawArrays(gl.TRIANGLES, 0, 6);
      animationFrameId = requestAnimationFrame(render);
    };
    render();

    return () => {
      window.removeEventListener('resize', resize);
      cancelAnimationFrame(animationFrameId);
      gl.deleteProgram(program);
    };
  }, [variant, speed]);

  return <canvas ref={canvasRef} className={`w-full h-full block ${className}`} />;
}
