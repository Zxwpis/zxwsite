import { useState, useCallback, useRef } from 'react';
import { motion } from 'framer-motion';
import { Lock, RefreshCw, ShieldCheck } from 'lucide-react';

interface BotCheckProps {
  onVerify: () => void;
}

interface Challenge {
  a: number;
  b: number;
  op: '+' | '-';
}

function generateChallenge(): Challenge {
  const op: Challenge['op'] = Math.random() < 0.5 ? '+' : '-';
  if (op === '+') {
    // Two single/double-digit numbers — easy mental math on any device.
    return { a: Math.floor(Math.random() * 9) + 1, b: Math.floor(Math.random() * 9) + 1, op };
  }
  // For subtraction, keep `a >= b` so the result is never negative.
  const a = Math.floor(Math.random() * 9) + 5;
  const b = Math.floor(Math.random() * a) + 1;
  return { a, b, op };
}

function solve(challenge: Challenge) {
  return challenge.op === '+' ? challenge.a + challenge.b : challenge.a - challenge.b;
}

export function BotCheck({ onVerify }: BotCheckProps) {
  const [challenge, setChallenge] = useState<Challenge>(generateChallenge);
  const [answer, setAnswer] = useState('');
  const [error, setError] = useState(false);
  const [shakeKey, setShakeKey] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const refresh = useCallback(() => {
    setChallenge(generateChallenge());
    setAnswer('');
    setError(false);
  }, []);

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      const trimmed = answer.trim();
      if (trimmed !== '' && Number(trimmed) === solve(challenge)) {
        onVerify();
        return;
      }
      setError(true);
      setShakeKey((k) => k + 1);
      setChallenge(generateChallenge());
      setAnswer('');
      inputRef.current?.focus();
    },
    [answer, challenge, onVerify],
  );

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-[100] flex items-center justify-center bg-bg/98 backdrop-blur-2xl px-4"
    >
      {/* Background Effects */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-accent/10 rounded-full blur-[150px]" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 30, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.5, ease: [0.23, 1, 0.32, 1] }}
        className="relative w-full max-w-md"
      >
        {/* Glow Effect */}
        <div className="absolute -inset-1 bg-gradient-to-r from-accent via-accent to-accent rounded-3xl blur-xl opacity-30 animate-pulse" />

        {/* Card */}
        <div className="relative glass-card p-6 sm:p-8 md:p-10">
          {/* Logo */}
          <motion.div
            className="flex justify-center mb-6 sm:mb-8"
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: 0.2, duration: 0.5 }}
          >
            <div className="relative">
              <div className="absolute inset-0 bg-accent/30 rounded-2xl blur-xl animate-pulse" />
              <img
                src="/logo.png"
                alt="ZXWY V3 Logo"
                className="relative w-20 h-20 sm:w-24 sm:h-24 rounded-2xl object-contain"
                style={{
                  filter: 'drop-shadow(0 0 20px rgba(54,254,53,0.3))',
                }}
              />
            </div>
          </motion.div>

          {/* Title */}
          <motion.h2
            className="text-xl sm:text-2xl md:text-3xl font-bold text-center mb-3"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
          >
            <span className="gradient-text">Human Verification</span>
          </motion.h2>

          {/* Description */}
          <motion.p
            className="text-text-dim text-center mb-6 sm:mb-8 text-sm md:text-base"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
          >
            To access <strong className="text-text">ZXWY V3</strong>, please solve the captcha below to prove
            you're human.
          </motion.p>

          {/* Captcha */}
          <motion.form
            key={shakeKey}
            onSubmit={handleSubmit}
            initial={{ opacity: 0, y: 10 }}
            animate={
              error
                ? { opacity: 1, y: 0, x: [0, -8, 8, -6, 6, 0] }
                : { opacity: 1, y: 0 }
            }
            transition={{ delay: error ? 0 : 0.5, duration: error ? 0.4 : 0.3 }}
            className="space-y-3"
          >
            <div className="flex items-center gap-3">
              <div className="flex flex-1 items-center justify-center gap-2 rounded-xl border-2 border-accent/50 bg-bg/80 backdrop-blur-sm py-3.5 px-4">
                <Lock className="h-4 w-4 shrink-0 text-accent" aria-hidden="true" />
                <span className="font-mono text-lg sm:text-xl font-bold tracking-wide text-text select-none">
                  {challenge.a} {challenge.op} {challenge.b} =
                </span>
              </div>
              <button
                type="button"
                onClick={refresh}
                aria-label="New captcha"
                className="grid h-[52px] w-[52px] shrink-0 place-items-center rounded-xl border border-accent/30 text-accent transition-colors hover:bg-accent/10"
              >
                <RefreshCw className="h-4 w-4" />
              </button>
            </div>

            <input
              ref={inputRef}
              type="tel"
              inputMode="numeric"
              autoComplete="off"
              value={answer}
              onChange={(e) => {
                setAnswer(e.target.value.replace(/[^0-9-]/g, ''));
                setError(false);
              }}
              placeholder="Your answer"
              aria-label="Captcha answer"
              aria-invalid={error}
              className={`w-full rounded-xl border-2 bg-bg/80 backdrop-blur-sm py-3.5 px-4 text-center text-base font-semibold text-text outline-none transition-colors placeholder:text-text-muted focus:border-accent ${
                error ? 'border-red-500/60' : 'border-accent/50'
              }`}
            />

            <button
              type="submit"
              className="group relative flex w-full items-center justify-center gap-2 rounded-xl bg-accent py-3.5 px-6 font-semibold text-black transition-transform duration-200 hover:scale-[1.01] active:scale-[0.99]"
            >
              <ShieldCheck className="h-5 w-5" />
              Verify
            </button>

            {error && (
              <p className="text-center text-xs font-medium text-red-500">
                Not quite — try the new equation below.
              </p>
            )}
          </motion.form>

          {/* Hint */}
          <motion.p
            className="text-xs text-text-muted text-center mt-5"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.6 }}
          >
            Solve the equation • No personal data collected
          </motion.p>

          {/* ZXWY V3 Badge */}
          <motion.div
            className="flex justify-center mt-6"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.7 }}
          >
            <span className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-accent/10 border border-accent/30 text-xs font-medium text-accent">
              <span className="w-2 h-2 rounded-full bg-accent animate-pulse" />
              ZXWY V3
            </span>
          </motion.div>
        </div>
      </motion.div>
    </motion.div>
  );
}
