import { useEffect, useRef } from 'react';
import type { RefObject } from 'react';
import { ArrowUpRight, CreditCard, EyeOff, Plus, Shield, TrendingUp } from 'lucide-react';
import gsap from 'gsap';
import { SplitText } from 'gsap/SplitText';
import { SilkShader } from '../components/SilkShader';
import FaultyTerminal from '../components/FaultyTerminal';
import { GlyphMatrix } from '../components/GlyphMatrix';
import { useCountUp } from '../lib/anim';

gsap.registerPlugin(SplitText);

const reducedMotion = () =>
  typeof window !== 'undefined' &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;

export function Hero() {
  const containerRef = useRef<HTMLDivElement>(null);
  const badgeRef = useRef<HTMLDivElement>(null);
  const titleTextRef = useRef<HTMLSpanElement>(null);
  const titleSubRef = useRef<HTMLSpanElement>(null);
  const statsContainerRef = useRef<HTMLDivElement>(null);
  const fpsRef = useCountUp(40, (n) => `+${Math.round(n)}%`);
  const latencyRef = useCountUp(30, (n) => `-${Math.round(n)}%`);

  useEffect(() => {
    const tl = gsap.timeline();
    const splits: SplitText[] = [];

    if (!reducedMotion() && titleTextRef.current && titleSubRef.current) {
      // Split into per-character spans for the stagger, but mask at the LINE level
      // (`mask: 'lines'`) rather than per-char — a per-char mask box is cropped tightly to
      // each glyph and slices off descenders (g/p/q/y). Masking the whole line instead keeps
      // the full line-height (room for descenders) while each char still animates on its own.
      const lineOne = new SplitText(titleTextRef.current, { type: 'chars,words', mask: 'lines' });
      const lineTwo = new SplitText(titleSubRef.current, { type: 'chars,words', mask: 'lines' });
      splits.push(lineOne, lineTwo);

      tl.fromTo(badgeRef.current,
        { opacity: 0, y: 16 },
        { opacity: 1, y: 0, duration: 0.35, ease: 'power3.out' }
      )
      .fromTo(lineOne.chars,
        { opacity: 0, yPercent: 130, rotateZ: 6, filter: 'blur(14px)' },
        { opacity: 1, yPercent: 0, rotateZ: 0, filter: 'blur(0px)', duration: 0.55, ease: 'expo.out', stagger: 0.012 },
        '-=0.15'
      )
      .fromTo(lineTwo.chars,
        { opacity: 0, yPercent: 130, rotateZ: 6, filter: 'blur(14px)' },
        { opacity: 1, yPercent: 0, rotateZ: 0, filter: 'blur(0px)', duration: 0.55, ease: 'expo.out', stagger: 0.012 },
        '-=0.45'
      )
      .fromTo(statsContainerRef.current?.children || [],
        { opacity: 0, y: 28 },
        { opacity: 1, y: 0, duration: 0.4, stagger: 0.05, ease: 'power3.out' },
        '-=0.3'
      );
    } else {
      // Reduced-motion / no title refs fallback — simple fade-up, no character splitting.
      tl.fromTo(badgeRef.current,
        { opacity: 0, y: 16 },
        { opacity: 1, y: 0, duration: 0.35, ease: 'power3.out' }
      )
      .fromTo([titleTextRef.current, titleSubRef.current],
        { opacity: 0, y: 24 },
        { opacity: 1, y: 0, duration: 0.45, ease: 'power3.out' },
        '-=0.2'
      )
      .fromTo(statsContainerRef.current?.children || [],
        { opacity: 0, y: 28 },
        { opacity: 1, y: 0, duration: 0.4, stagger: 0.05, ease: 'power3.out' },
        '-=0.3'
      );
    }

    return () => {
      tl.kill();
      splits.forEach((split) => split.revert());
    };
  }, []);

  const scrollTo = (selector: string) => {
    document.querySelector(selector)?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <section
      id="hero"
      ref={containerRef}
      className="relative min-h-screen flex items-center pt-32 pb-24 overflow-hidden bg-transparent"
    >
      {/* Faulty-terminal background — test effect. The shader itself always paints an opaque black
          field with bright specks, so to get a white page with faint grey flecks we invert + desaturate
          it via CSS filters rather than fighting the shader math. No edge fades — full-bleed, flush with
          the section. pointer-events left enabled so mouseReact can track the cursor; it sits at z-0 so
          it never intercepts clicks on the content above. */}
      <div className="absolute inset-0 z-0 bg-white">
        <FaultyTerminal
          className="invert grayscale"
          scale={3.2}
          gridMul={[2, 1]}
          digitSize={1}
          timeScale={0.5}
          scanlineIntensity={0.4}
          glitchAmount={1}
          flickerAmount={0.8}
          noiseAmp={1}
          chromaticAberration={0}
          dither={0}
          curvature={0}
          tint="#ffffff"
          mouseReact
          mouseStrength={0.3}
          pageLoadAnimation
          brightness={0.1}
        />
      </div>

      {/* Both columns share `items-start`, and the badge/h1 baseline lines up with the top edge of
          the bento grid on the right — one shared top row instead of two independently centred blocks. */}
      <div className="section-container relative z-10 w-full">
        <div className="grid lg:grid-cols-[1.05fr_1fr] gap-14 lg:gap-20 items-start">
          {/* Left: editorial statement */}
          <div className="space-y-8">
            <div ref={badgeRef} className="flex">
              <span className="pill-outline">
                <span className="h-2 w-2 rounded-full bg-[#36FE35]" />
                ZXWY V3.0 is live
              </span>
            </div>

            <h1 className="display-dot text-[clamp(2.5rem,5.6vw,4.25rem)] text-[#16191a]">
              <span ref={titleTextRef} className="block">
                Designed for faster,
              </span>
              <span ref={titleSubRef} className="block">
                quieter, sharper machines
              </span>
            </h1>

            <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4 pt-2">
              <button
                onClick={() => scrollTo('#features')}
                className="group inline-flex items-center gap-2 rounded-full bg-[#16191a] px-7 py-3.5 text-sm font-semibold text-white transition-all duration-300 hover:bg-black hover:-translate-y-0.5"
              >
                View features
                <ArrowUpRight className="h-4 w-4 transition-transform duration-300 group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
              </button>
              <button
                onClick={() => scrollTo('#pricing')}
                className="group inline-flex items-center gap-2 rounded-full border border-[#16191a]/15 bg-white/70 px-7 py-3.5 text-sm font-semibold text-[#16191a] backdrop-blur-md transition-all duration-300 hover:border-[#16191a]/40 hover:-translate-y-0.5"
              >
                <CreditCard className="h-4 w-4" />
                Buy
              </button>
            </div>
          </div>

          {/* Right: bento metrics */}
          <div ref={statsContainerRef} className="grid grid-cols-2 gap-4">
            <div className="group bento-paper flex flex-col justify-between min-h-[210px]">
              <div className="absolute inset-0 opacity-90">
                <SilkShader variant="lime" speed={0.7} />
              </div>
              <span className="plus-dot">
                <Plus className="h-4 w-4" />
              </span>
              <div className="relative mt-auto">
                <p ref={fpsRef as RefObject<HTMLParagraphElement>} className="metric text-[#16191a]" />
                <p className="metric-caption text-[#16191a]">FPS gain on typical rigs</p>
              </div>
            </div>

            <div className="group bento-ink flex flex-col justify-between min-h-[210px]">
              <div className="absolute inset-0 mask-radial-soft opacity-95">
                <SilkShader variant="dark" speed={0.6} />
              </div>
              <span className="pill-lime relative w-fit">
                <TrendingUp className="h-3 w-3" />
                latency
              </span>
              <div className="relative mt-auto">
                <p ref={latencyRef as RefObject<HTMLParagraphElement>} className="metric text-white" />
                <p className="metric-caption text-white">less input delay, on average</p>
              </div>
            </div>

            <div className="group bento-lime flex flex-col justify-between min-h-[190px]">
              <span className="plus-dot">
                <Plus className="h-4 w-4" />
              </span>
              <Shield className="h-6 w-6" />
              <div className="mt-auto">
                <p className="metric">100%</p>
                <p className="metric-caption">reversible & safe</p>
              </div>
            </div>

            <div className="group bento-paper flex flex-col justify-between min-h-[190px]">
              <div className="absolute inset-0 opacity-70">
                <GlyphMatrix color="#16191a" cellSize={13} mutationRate={0.03} fadeBottom={0.75} />
              </div>
              <span className="plus-dot">
                <EyeOff className="h-4 w-4" />
              </span>
              <div className="relative mt-auto">
                <p className="metric text-[#16191a] text-[clamp(1.6rem,2.6vw,2.2rem)]">Zero telemetry</p>
                <p className="metric-caption text-[#16191a]">nothing phones home, ever</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
