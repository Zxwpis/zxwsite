import { useState } from 'react';
import { motion, type Transition } from 'framer-motion';
import { cn } from '../lib/utils';

// A hover-triggered 3D letter-flip effect built on framer-motion (already used everywhere
// else in this codebase). Each character is a tiny two-sided "card" (front face + back face)
// rotating around the X axis. Hover state is tracked explicitly via React state and passed
// down as an `animate` target to every character — this avoids relying on framer-motion's
// implicit variant-propagation-through-context behaviour, which turned out to not actually
// flip anything in this project's React/framer-motion version combo.

const DEFAULT_TRANSITION: Transition = { type: 'spring', damping: 20, stiffness: 260 };

interface Text3DFlipProps {
  children: string;
  as?: 'p' | 'span' | 'div' | 'h2' | 'h3';
  className?: string;
  textClassName?: string;
  flipTextClassName?: string;
  staggerDuration?: number;
  staggerFrom?: 'first' | 'last' | 'center';
  transition?: Transition;
  rotateDirection?: 'top' | 'bottom';
}

function getStaggerDelay(
  index: number,
  total: number,
  from: 'first' | 'last' | 'center',
  duration: number
) {
  if (from === 'first') return index * duration;
  if (from === 'last') return (total - 1 - index) * duration;
  const center = Math.floor(total / 2);
  return Math.abs(center - index) * duration;
}

const MOTION_TAGS = {
  p: motion.p,
  span: motion.span,
  div: motion.div,
  h2: motion.h2,
  h3: motion.h3,
} as const;

export default function Text3DFlip({
  children,
  as = 'p',
  className,
  textClassName,
  flipTextClassName,
  staggerDuration = 0.025,
  staggerFrom = 'center',
  transition = DEFAULT_TRANSITION,
  rotateDirection = 'top',
}: Text3DFlipProps) {
  const [hovered, setHovered] = useState(false);
  const chars = Array.from(children);
  // "top": front tips back/away and up, back face swings down into view (and vice versa).
  const sign = rotateDirection === 'top' ? -1 : 1;
  const MotionTag = MOTION_TAGS[as];

  return (
    <MotionTag
      onHoverStart={() => setHovered(true)}
      onHoverEnd={() => setHovered(false)}
      className={cn(
        'relative inline-flex flex-nowrap select-none [perspective:700px]',
        className
      )}
    >
      <span className="sr-only">{children}</span>

      {chars.map((char, index) => {
        const delay = getStaggerDelay(index, chars.length, staggerFrom, staggerDuration);
        const charTransition = { ...transition, delay };

        return (
          <span
            key={index}
            aria-hidden="true"
            className="relative inline-block"
            style={{ transformStyle: 'preserve-3d' }}
          >
            {/* Front face — visible at rest, flips away on hover */}
            <motion.span
              className={cn('block backface-hidden', textClassName)}
              style={{ transformStyle: 'preserve-3d' }}
              animate={{ rotateX: hovered ? sign * 90 : 0 }}
              transition={charTransition}
            >
              {char === ' ' ? '\u00A0' : char}
            </motion.span>
            {/* Back face — starts rotated out of view, swings into place on hover */}
            <motion.span
              className={cn('absolute inset-0 block backface-hidden', flipTextClassName)}
              style={{ transformStyle: 'preserve-3d' }}
              animate={{ rotateX: hovered ? 0 : sign * -90 }}
              transition={charTransition}
            >
              {char === ' ' ? '\u00A0' : char}
            </motion.span>
          </span>
        );
      })}
    </MotionTag>
  );
}
