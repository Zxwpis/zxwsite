import { motion } from 'framer-motion';
import { AlertTriangle, Shield, Info } from 'lucide-react';

export function Warning() {
  return (
    <section className="relative py-12">
      <div className="section-container">
        <motion.div 
          className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-yellow-500/10 via-orange-500/5 to-transparent border border-yellow-500/30 p-6 md:p-8"
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
        >
          {/* Background Pattern */}
          <div className="absolute inset-0 opacity-5">
            <div className="absolute inset-0" style={{
              backgroundImage: `repeating-linear-gradient(
                45deg,
                transparent,
                transparent 10px,
                rgba(234, 179, 8, 0.1) 10px,
                rgba(234, 179, 8, 0.1) 20px
              )`
            }} />
          </div>

          <div className="relative flex flex-col md:flex-row items-start md:items-center gap-4 md:gap-6">
            {/* Icon */}
            <div className="w-14 h-14 rounded-xl bg-yellow-500/10 border border-yellow-500/30 flex items-center justify-center flex-shrink-0">
              <AlertTriangle className="w-7 h-7 text-yellow-500" />
            </div>

            {/* Content */}
            <div className="flex-1">
              <h3 className="text-lg font-semibold text-yellow-500 mb-2">
                Use at Your Own Risk
              </h3>
              <div className="space-y-2 text-sm text-white/60">
                <p>
                  While ZXWY V2 is designed to be safe and all tweaks are reversible, 
                  any system modification carries inherent risks. By using this software, you acknowledge that:
                </p>
                <ul className="space-y-1 ml-4">
                  <li className="flex items-start gap-2">
                    <span className="text-yellow-500 mt-1">•</span>
                    <span>You should always create a system restore point before applying any tweaks</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-yellow-500 mt-1">•</span>
                    <span>Results may vary depending on your hardware and current system configuration</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-yellow-500 mt-1">•</span>
                    <span>The developers are not responsible for any damage or data loss</span>
                  </li>
                </ul>
              </div>
            </div>

            {/* Safety Badge */}
            <div className="flex-shrink-0">
              <div className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[#22c55e]/10 border border-[#22c55e]/30">
                <Shield className="w-5 h-5 text-[#22c55e]" />
                <span className="text-sm font-medium text-[#22c55e]">Auto Backup Enabled</span>
              </div>
            </div>
          </div>

          {/* Bottom Note */}
          <div className="relative mt-6 pt-4 border-t border-yellow-500/10 flex items-center gap-2 text-xs text-white/50">
            <Info className="w-4 h-4 text-yellow-500" />
            <span>
              If you experience any issues, you can restore your system using the automatic backup 
              created before applying tweaks.
            </span>
          </div>
        </motion.div>
      </div>
    </section>
  );
}
