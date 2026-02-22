import { useState, useRef, useCallback } from 'react';
import { Shield, Lock } from 'lucide-react';

interface BotCheckProps {
  onVerify: () => void;
}

export function BotCheck({ onVerify }: BotCheckProps) {
  const [isHolding, setIsHolding] = useState(false);
  const [progress, setProgress] = useState(0);
  const holdTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const progressIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const REQUIRED_HOLD_TIME = 1800; // 1.8 seconds
  const PROGRESS_INTERVAL = 16; // ~60fps

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
    
    // Progress animation
    let currentProgress = 0;
    const increment = 100 / (REQUIRED_HOLD_TIME / PROGRESS_INTERVAL);
    
    progressIntervalRef.current = setInterval(() => {
      currentProgress += increment;
      setProgress(Math.min(currentProgress, 100));
    }, PROGRESS_INTERVAL);
    
    // Verification timeout
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/95 backdrop-blur-xl animate-fade-in">
      <div className="relative w-full max-w-md mx-4">
        {/* Glow Effect */}
        <div className="absolute -inset-1 bg-gradient-to-r from-primary via-accent to-primary rounded-2xl blur-xl opacity-50 animate-pulse-glow" />
        
        {/* Card */}
        <div className="relative bg-card border border-border rounded-2xl p-8 shadow-2xl">
          {/* Icon */}
          <div className="flex justify-center mb-6">
            <div className="relative">
              <div className="absolute inset-0 bg-primary/20 rounded-full blur-xl animate-pulse" />
              <div className="relative w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center border border-primary/30">
                <Shield className="w-8 h-8 text-primary" />
              </div>
            </div>
          </div>
          
          {/* Title */}
          <h2 className="text-2xl font-bold text-center mb-2">
            <span className="zxwy-gradient-text">Human Verification</span>
          </h2>
          
          {/* Description */}
          <p className="text-muted-foreground text-center mb-6">
            To access <strong className="text-foreground">ZXWY V2</strong>, please verify you're human by holding the button below.
          </p>
          
          {/* Hold Button */}
          <button
            className="relative w-full group"
            onMouseDown={startHold}
            onMouseUp={endHold}
            onMouseLeave={endHold}
            onTouchStart={startHold}
            onTouchEnd={endHold}
            onTouchCancel={endHold}
          >
            {/* Progress Background */}
            <div className="absolute inset-0 bg-primary/20 rounded-xl overflow-hidden">
              <div 
                className="h-full bg-primary transition-all duration-75 ease-linear"
                style={{ width: `${progress}%` }}
              />
            </div>
            
            {/* Button Content */}
            <div 
              className={`
                relative flex items-center justify-center gap-3 py-4 px-6 rounded-xl
                border-2 border-primary/50 bg-card/50 backdrop-blur-sm
                transition-all duration-200
                ${isHolding ? 'border-primary scale-[0.98]' : 'hover:border-primary hover:bg-primary/5'}
              `}
            >
              <Lock className={`w-5 h-5 transition-colors ${isHolding ? 'text-primary-foreground' : 'text-primary'}`} />
              <span className={`font-semibold transition-colors ${isHolding ? 'text-primary-foreground' : 'text-foreground'}`}>
                {isHolding ? 'Verifying...' : 'Press & Hold to Verify'}
              </span>
            </div>
          </button>
          
          {/* Hint */}
          <p className="text-xs text-muted-foreground text-center mt-4">
            Hold for 2 seconds • No personal data collected
          </p>
          
          {/* ZXWY V2 Badge */}
          <div className="flex justify-center mt-6">
            <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/20 text-xs font-medium text-primary">
              <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
              ZXWY V2
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
