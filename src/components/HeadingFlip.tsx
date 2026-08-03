import { useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { cn } from '../lib/utils';

// A repeatable, per-letter 3D flip for section headings: alternates between two texts
// (front/back/front/back/...) on every hover. Whichever text is currently showing always
// flips fully away first, letter by letter — only after it's completely gone (plus a
// short pause) does the other one flip in. Each letter also fades alongside the rotation
// so it fully disappears at the 90° edge instead of leaving a faint hairline sliver.
// Letters are grouped by word (not one flat run) so wrapping to a new line only ever
// happens between words, never in the middle of one.

const FLIP_DURATION = 0.22;
const GAP_AFTER_OUT = 0.12;

/** A run of text, optionally rendered in the brand lime accent color. */
export interface HeadingSegment {
  text: string;
  lime?: boolean;
}

interface FlatChar {
  char: string;
  lime: boolean;
}

function flatten(segments: HeadingSegment[]): FlatChar[] {
  return segments.flatMap((segment) =>
    Array.from(segment.text).map((char) => ({ char, lime: Boolean(segment.lime) }))
  );
}

/** Groups characters into words (a run of non-space chars, or a single space) so a word
 *  never splits across a line wrap. */
function groupWords(chars: FlatChar[]): FlatChar[][] {
  const words: FlatChar[][] = [];
  let current: FlatChar[] = [];
  for (const c of chars) {
    if (c.char === ' ') {
      if (current.length) {
        words.push(current);
        current = [];
      }
      words.push([c]);
    } else {
      current.push(c);
    }
  }
  if (current.length) words.push(current);
  return words;
}

function totalFlipTime(count: number, staggerDuration: number) {
  return count > 0 ? (count - 1) * staggerDuration + FLIP_DURATION : 0;
}

interface LayerProps {
  chars: FlatChar[];
  active: boolean;
  hiddenAngle: number;
  staggerDuration: number;
  baseDelay: number;
}

function Layer({ chars, active, hiddenAngle, staggerDuration, baseDelay }: LayerProps) {
  const shown = { rotateX: 0, opacity: 1 };
  const hidden = { rotateX: hiddenAngle, opacity: 0 };
  const words = groupWords(chars);
  let globalIndex = 0;

  return (
    <span
      className="relative col-start-1 row-start-1 flex flex-wrap content-center items-center justify-center self-stretch"
      style={{ transformStyle: 'preserve-3d' }}
    >
      {words.map((word, wordIdx) => {
        const startIndex = globalIndex;
        globalIndex += word.length;

        return (
          <span key={wordIdx} className="inline-flex" style={{ transformStyle: 'preserve-3d' }}>
            {word.map((c, i) => {
              const index = startIndex + i;
              return (
                <motion.span
                  key={i}
                  aria-hidden={!active}
                  className={cn('inline-block backface-hidden', c.lime && 'text-[#36FE35]')}
                  style={{ transformStyle: 'preserve-3d' }}
                  initial={active ? shown : hidden}
                  animate={active ? shown : hidden}
                  transition={{
                    duration: FLIP_DURATION,
                    ease: 'easeInOut',
                    delay: baseDelay + index * staggerDuration,
                  }}
                >
                  {c.char === ' ' ? '\u00A0' : c.char}
                </motion.span>
              );
            })}
          </span>
        );
      })}
    </span>
  );
}

interface HeadingFlipProps {
  front: HeadingSegment[];
  back: HeadingSegment[];
  className?: string;
  as?: 'h1' | 'h2' | 'h3';
  rotateDirection?: 'top' | 'bottom';
  staggerDuration?: number;
}

const TAGS = { h1: 'h1', h2: 'h2', h3: 'h3' } as const;

export function HeadingFlip({
  front,
  back,
  className,
  as = 'h2',
  rotateDirection = 'top',
  staggerDuration = 0.01,
}: HeadingFlipProps) {
  const ref = useRef<HTMLHeadingElement>(null);
  const [showBack, setShowBack] = useState(false);

  const sign: 1 | -1 = rotateDirection === 'top' ? -1 : 1;
  const frontChars = flatten(front);
  const backChars = flatten(back);
  const frontActive = !showBack;
  const backActive = showBack;

  const frontTotal = totalFlipTime(frontChars.length, staggerDuration);
  const backTotal = totalFlipTime(backChars.length, staggerDuration);

  // Whichever side is becoming active waits for the other side's full flip-out plus a
  // short pause; the side becoming inactive always starts flipping out immediately.
  const frontDelay = frontActive ? backTotal + GAP_AFTER_OUT : 0;
  const backDelay = backActive ? frontTotal + GAP_AFTER_OUT : 0;
  const Tag = TAGS[as];

  return (
    <Tag
      ref={ref}
      onMouseEnter={() => setShowBack((v) => !v)}
      className={cn('relative grid cursor-default text-center [perspective:900px]', className)}
    >
      <Layer
        chars={frontChars}
        active={frontActive}
        hiddenAngle={sign * 90}
        staggerDuration={staggerDuration}
        baseDelay={frontDelay}
      />
      <Layer
        chars={backChars}
        active={backActive}
        hiddenAngle={sign * -90}
        staggerDuration={staggerDuration}
        baseDelay={backDelay}
      />
    </Tag>
  );
}
