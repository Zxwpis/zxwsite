// Pricing section - no state needed
import { motion } from 'framer-motion';
import { Check, Sparkles, Crown, Rocket, ExternalLink } from 'lucide-react';

interface PricingPlan {
  id: string;
  name: string;
  price: string;
  description: string;
  icon: typeof Sparkles;
  features: string[];
  highlighted?: boolean;
  paypalUrl: string;
}

const plans: PricingPlan[] = [
  {
    id: 'standard',
    name: 'Standard',
    price: '$7',
    description: 'Perfect for casual gamers looking for a performance boost.',
    icon: Sparkles,
    features: [
      'Windows optimization',
      'Custom power plan',
      'Basic service debloat',
      'Registry cleanup',
      'Email support',
    ],
    paypalUrl: 'https://www.paypal.com/ncp/payment/UJ25T4QCY7DZ6',
  },
  {
    id: 'ultimate',
    name: 'Ultimate',
    price: '$19',
    description: 'Complete optimization package for serious gamers.',
    icon: Crown,
    highlighted: true,
    features: [
      'Everything in Standard',
      'Advanced service debloat',
      'Deep registry tweaks',
      'BIOS optimization guide',
      'Secret GPU & CPU tweaks',
      'Priority support',
      'Lifetime updates',
    ],
    paypalUrl: 'https://www.paypal.com/ncp/payment/HNLPG3NPEJ3B8',
  },
  {
    id: 'max',
    name: 'Max',
    price: '$12',
    description: 'Balanced optimization for already productive systems.',
    icon: Rocket,
    features: [
      'Everything in Standard',
      'Component-independent tweaks',
      'Network optimization',
      'Storage optimization',
      'Discord support',
    ],
    paypalUrl: 'https://www.paypal.com/ncp/payment/JELVMDHCE5EJJ',
  },
];

const containerVariants = {
  hidden: { opacity: 0 },
  visible: {
    opacity: 1,
    transition: {
      staggerChildren: 0.15,
    },
  },
};

const itemVariants = {
  hidden: { opacity: 0, y: 40 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.6,
    },
  },
};

export function Pricing() {
  return (
    <section id="pricing" className="relative py-24 md:py-32 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[600px] bg-[#22c55e]/5 rounded-full blur-[150px]" />
      </div>

      <div className="section-container relative z-10">
        {/* Section Header */}
        <motion.div 
          className="text-center max-w-3xl mx-auto mb-16"
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, ease: [0.23, 1, 0.32, 1] }}
        >
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-[#22c55e]/10 border border-[#22c55e]/30 mb-6">
            <Crown className="w-4 h-4 text-[#22c55e]" />
            <span className="text-sm font-medium text-[#22c55e]">Premium Plans</span>
          </div>
          <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-6">
            Choose Your <span className="gradient-text">Optimization Level</span>
          </h2>
          <p className="text-lg text-white/60">
            Upgrade to a premium plan for advanced optimizations and personalized support. 
            All plans include our core V2 features.
          </p>
        </motion.div>

        {/* Pricing Grid */}
        <motion.div 
          className="grid md:grid-cols-3 gap-6 lg:gap-8 max-w-6xl mx-auto"
          variants={containerVariants}
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true, margin: '-100px' }}
        >
          {plans.map((plan) => (
            <motion.div
              key={plan.id}
              variants={itemVariants}
              whileHover={{ y: -10, transition: { duration: 0.3 } }}
              className={`
                relative rounded-2xl p-6 lg:p-8 transition-all duration-500
                ${plan.highlighted 
                  ? 'bg-gradient-to-b from-[#22c55e]/20 to-[#22c55e]/5 border-2 border-[#22c55e]/50' 
                  : 'glass-card'
                }
              `}
            >
              {/* Popular Badge */}
              {plan.highlighted && (
                <div className="absolute -top-4 left-1/2 -translate-x-1/2">
                  <span className="px-4 py-1.5 rounded-full bg-[#22c55e] text-black text-sm font-semibold shadow-lg shadow-[#22c55e]/30">
                    Most Popular
                  </span>
                </div>
              )}

              {/* Plan Header */}
              <div className="text-center mb-8">
                <div className={`
                  w-16 h-16 rounded-xl mx-auto mb-4 flex items-center justify-center
                  ${plan.highlighted ? 'bg-[#22c55e]/20' : 'bg-white/5'}
                `}>
                  <plan.icon className="w-8 h-8 text-[#22c55e]" />
                </div>
                <h3 className="text-2xl font-bold mb-2">{plan.name}</h3>
                <div className="flex items-baseline justify-center gap-1 mb-3">
                  <span className="text-4xl lg:text-5xl font-bold">{plan.price}</span>
                  <span className="text-white/50">one-time</span>
                </div>
                <p className="text-sm text-white/50">{plan.description}</p>
              </div>

              {/* Features */}
              <ul className="space-y-3 mb-8">
                {plan.features.map((feature, index) => (
                  <motion.li 
                    key={feature} 
                    className="flex items-start gap-3"
                    initial={{ opacity: 0, x: -10 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: index * 0.05 }}
                  >
                    <div className="w-5 h-5 rounded-full bg-[#22c55e]/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                      <Check className="w-3 h-3 text-[#22c55e]" />
                    </div>
                    <span className="text-sm text-white/70">{feature}</span>
                  </motion.li>
                ))}
              </ul>

              {/* CTA Button */}
              <motion.a
                href={plan.paypalUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="block"
                whileHover={{ scale: 1.03 }}
                whileTap={{ scale: 0.97 }}
              >
                <button className={`w-full ${plan.highlighted ? 'btn-neon' : 'btn-secondary'} gap-2`}>
                  Get {plan.name}
                  <ExternalLink className="w-4 h-4" />
                </button>
              </motion.a>
            </motion.div>
          ))}
        </motion.div>

        {/* Support Note */}
        <motion.div 
          className="text-center mt-12"
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ delay: 0.5 }}
        >
          <p className="text-white/50">
            Have questions about which plan to choose?{' '}
            <a 
              href="https://discord.gg/UQmBUXct" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-[#22c55e] hover:underline"
            >
              Contact us on Discord
            </a>
          </p>
        </motion.div>
      </div>
    </section>
  );
}
