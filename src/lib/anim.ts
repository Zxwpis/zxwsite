import { useEffect, useRef } from 'react';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { animate, inView, stagger } from 'motion';

gsap.registerPlugin(ScrollTrigger);

export const EASE = 'power3.out';

const reducedMotion = () =>
  typeof window !== 'undefined' &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/**
 * GSAP + ScrollTrigger reveal for a whole section.
 * Every descendant carrying [data-reveal] rises into place, staggered in DOM order.
 */
export function useSectionReveal<T extends HTMLElement = HTMLElement>(
  options: { y?: number; stagger?: number; start?: string } = {}
) {
  const ref = useRef<T>(null);

  useEffect(() => {
    const root = ref.current;
    if (!root) return;

    const targets = root.querySelectorAll<HTMLElement>('[data-reveal]');
    if (!targets.length) return;

    if (reducedMotion()) {
      gsap.set(targets, { opacity: 1, y: 0 });
      return;
    }

    const ctx = gsap.context(() => {
      gsap.fromTo(
        targets,
        { opacity: 0, y: options.y ?? 34 },
        {
          opacity: 1,
          y: 0,
          duration: 0.85,
          ease: EASE,
          stagger: options.stagger ?? 0.09,
          scrollTrigger: {
            trigger: root,
            start: options.start ?? 'top 78%',
            once: true,
          },
        }
      );
    }, root);

    return () => ctx.revert();
  }, [options.start, options.stagger, options.y]);

  return ref;
}

/**
 * Gentle parallax drift tied to the page scroll — used for section glows / big type.
 */
export function useParallax<T extends HTMLElement = HTMLElement>(distance = 60) {
  const ref = useRef<T>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el || reducedMotion()) return;

    const ctx = gsap.context(() => {
      gsap.fromTo(
        el,
        { yPercent: -distance / 10 },
        {
          yPercent: distance / 10,
          ease: 'none',
          scrollTrigger: {
            trigger: el,
            start: 'top bottom',
            end: 'bottom top',
            scrub: true,
          },
        }
      );
    }, el);

    return () => ctx.revert();
  }, [distance]);

  return ref;
}

/**
 * Motion One: counts a numeric value up the first time the element enters the viewport.
 */
export function useCountUp(
  value: number,
  format: (n: number) => string = (n) => `${Math.round(n)}`
) {
  const ref = useRef<HTMLElement | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    if (reducedMotion()) {
      el.textContent = format(value);
      return;
    }

    el.textContent = format(0);
    return inView(
      el,
      () => {
        animate(0, value, {
          duration: 1.2,
          ease: [0.16, 1, 0.3, 1],
          onUpdate: (latest: number) => {
            el.textContent = format(latest);
          },
        });
      },
      { amount: 0.4 }
    );
  }, [value, format]);

  return ref;
}

/**
 * Motion One: fades a list of children in as soon as the container is seen.
 * Used where GSAP timelines would be overkill (nav, chips, tiny lists).
 */
export function motionListReveal(
  container: Element | null,
  selector: string,
  delay = 0
) {
  if (!container || reducedMotion()) return;
  const items = container.querySelectorAll(selector);
  if (!items.length) return;

  return inView(container, () => {
    animate(
      items,
      { opacity: [0, 1], transform: ['translateY(14px)', 'translateY(0px)'] },
      { duration: 0.5, delay: stagger(0.06, { startDelay: delay }), ease: [0.16, 1, 0.3, 1] }
    );
  });
}
