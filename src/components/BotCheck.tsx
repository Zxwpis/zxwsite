import { useState, useRef, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Lock, Shield } from 'lucide-react';

interface BotCheckProps {
  onVerify: () => void;
}

export function BotCheck({ onVerify }: BotCheckProps) {
  const [isHolding, setIsHolding] = useState(false);
  const [progress, setProgress] = useState(0);
  const holdTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const progressIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const REQUIRED_HOLD_TIME = 1800;
  const PROGRESS_INTERVAL = 16;

  const clearTimers = useCallback(() => {
    if (holdTimeoutRef.current) {
      clearTimeout(holdTimeoutRef.current);
      holdTimeoutRef.current = null;
    }
    if (progressIntervalRef.current) {
      clearInterval(progressIntervalRef.current);
      progressIntervalRef.current = null;
    }
  }, []);

  const startHold = useCallback(() => {
    setIsHolding(true);
    setProgress(0);
    
    let currentProgress = 0;
    const increment = 100 / (REQUIRED_HOLD_TIME / PROGRESS_INTERVAL);
    
    progressIntervalRef.current = setInterval(() => {
      currentProgress += increment;
      setProgress(Math.min(currentProgress, 100));
    }, PROGRESS_INTERVAL);
    
    holdTimeoutRef.current = setTimeout(() => {
      clearTimers();
      onVerify();
    }, REQUIRED_HOLD_TIME);
  }, [onVerify, clearTimers]);

  const endHold = useCallback(() => {
    setIsHolding(false);
    setProgress(0);
    clearTimers();
  }, [clearTimers]);

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-[100] flex items-center justify-center bg-bg/98 backdrop-blur-2xl"
    >
      {/* Background Effects */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-accent/10 rounded-full blur-[150px]" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 30, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.5, ease: [0.23, 1, 0.32, 1] }}
        className="relative w-full max-w-md mx-4"
      >
        {/* Glow Effect */}
        <div className="absolute -inset-1 bg-gradient-to-r from-accent via-accent to-accent rounded-3xl blur-xl opacity-30 animate-pulse" />
        
        {/* Card */}
        <div className="relative glass-card p-8 md:p-10">
          {/* Logo */}
          <motion.div 
            className="flex justify-center mb-8"
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: 0.2, duration: 0.5 }}
          >
            <div className="relative">
              <div className="absolute inset-0 bg-accent/30 rounded-2xl blur-xl animate-pulse" />
              <img 
                src="/logo.png" 
                alt="ZXWY V3 Logo" 
                className="relative w-24 h-24 rounded-2xl object-contain"
                style={{ 
                  filter: 'drop-shadow(0 0 20px rgba(54,254,53,0.3))',
                }}
              />
            </div>
          </motion.div>
          
          {/* Title */}
          <motion.h2 
            className="text-2xl md:text-3xl font-bold text-center mb-3"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
          >
            <span className="gradient-text">Human Verification</span>
          </motion.h2>
          
          {/* Description */}
          <motion.p 
            className="text-text-dim text-center mb-8 text-sm md:text-base"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
          >
            To access <strong className="text-text">ZXWY V3</strong>, please verify you're human by holding the button below.
          </motion.p>
          
          {/* Hold Button */}
          <motion.button
            className="relative w-full group"
            onMouseDown={startHold}
            onMouseUp={endHold}
            onMouseLeave={endHold}
            onTouchStart={startHold}
            onTouchEnd={endHold}
            onTouchCancel={endHold}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
          >
            {/* Progress Background */}
            <div className="absolute inset-0 bg-accent/20 rounded-xl overflow-hidden">
              <motion.div 
                className="h-full bg-gradient-to-r from-accent to-accent"
                style={{ width: `${progress}%` }}
                transition={{ duration: 0.05 }}
              />
            </div>
            
            {/* Button Content */}
            <div 
              className={`
                relative flex items-center justify-center gap-3 py-4 px-6 rounded-xl
                border-2 border-accent/50 bg-bg/80 backdrop-blur-sm
                transition-all duration-200
                ${isHolding ? 'border-accent' : 'hover:border-accent/80'}
              `}
            >
              {isHolding ? (
                <Shield className="w-5 h-5 text-black" />
              ) : (
                <Lock className="w-5 h-5 text-accent" />
              )}
              <span className={`font-semibold transition-colors ${isHolding ? 'text-black' : 'text-text'}`}>
                {isHolding ? 'Verifying...' : 'Press & Hold to Verify'}
              </span>
            </div>
          </motion.button>
          
          {/* Hint */}
          <motion.p 
            className="text-xs text-text-muted text-center mt-5"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.6 }}
          >
            Hold for 2 seconds • No personal data collected
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
