import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { 
  Check, 
  Sparkles, 
  Crown, 
  Rocket,
  ChevronLeft,
  ChevronRight,
  ExternalLink
} from 'lucide-react';

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

export function Pricing() {
  const [activeIndex, setActiveIndex] = useState(1);
  const [isAnimating, setIsAnimating] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('in-view');
          }
        });
      },
      { threshold: 0.1, rootMargin: '0px 0px -10% 0px' }
    );

    const elements = document.querySelectorAll('#pricing .animate-on-scroll');
    elements.forEach((el) => observer.observe(el));

    return () => observer.disconnect();
  }, []);

  const navigate = (direction: 'prev' | 'next') => {
    if (isAnimating) return;
    
    setIsAnimating(true);
    if (direction === 'prev') {
      setActiveIndex((prev) => (prev === 0 ? plans.length - 1 : prev - 1));
    } else {
      setActiveIndex((prev) => (prev === plans.length - 1 ? 0 : prev + 1));
    }
    
    setTimeout(() => setIsAnimating(false), 300);
  };

  const getCardStyle = (index: number) => {
    const diff = index - activeIndex;
    const normalizedDiff = ((diff + plans.length) % plans.length);
    
    if (normalizedDiff === 0) {
      return {
        transform: 'translateX(-50%) scale(1)',
        opacity: 1,
        zIndex: 30,
      };
    } else if (normalizedDiff === 1 || normalizedDiff === -2) {
      return {
        transform: 'translateX(30%) scale(0.85)',
        opacity: 0.6,
        zIndex: 20,
      };
    } else {
      return {
        transform: 'translateX(-130%) scale(0.85)',
        opacity: 0.6,
        zIndex: 20,
      };
    }
  };

  return (
    <section id="pricing" className="zxwy-section relative overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[600px] bg-primary/5 rounded-full blur-3xl" />
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <div className="text-center max-w-3xl mx-auto mb-16 animate-on-scroll">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-6">
            <Crown className="w-4 h-4 text-primary" />
            <span className="text-sm font-medium text-primary">Premium Plans</span>
          </div>
          <h2 className="text-4xl sm:text-5xl font-bold mb-6">
            Choose Your <span className="zxwy-gradient-text">Optimization Level</span>
          </h2>
          <p className="text-lg text-muted-foreground">
            Upgrade to a premium plan for advanced optimizations and personalized support. 
            All plans include our core V2 features.
          </p>
        </div>

        {/* Desktop Grid */}
        <div className="hidden lg:grid lg:grid-cols-3 gap-8 animate-on-scroll delay-1">
          {plans.map((plan) => (
            <div
              key={plan.id}
              className={`
                relative rounded-2xl p-8 transition-all duration-300
                ${plan.highlighted 
                  ? 'bg-card border-2 border-primary shadow-xl scale-105' 
                  : 'bg-card border border-border hover:border-primary/30'
                }
              `}
            >
              {/* Popular Badge */}
              {plan.highlighted && (
                <div className="absolute -top-4 left-1/2 -translate-x-1/2">
                  <span className="px-4 py-1 rounded-full bg-primary text-primary-foreground text-sm font-medium">
                    Most Popular
                  </span>
                </div>
              )}

              {/* Plan Header */}
              <div className="text-center mb-8">
                <div className={`
                  w-16 h-16 rounded-xl mx-auto mb-4 flex items-center justify-center
                  ${plan.highlighted ? 'bg-primary/20' : 'bg-primary/10'}
                `}>
                  <plan.icon className="w-8 h-8 text-primary" />
                </div>
                <h3 className="text-2xl font-bold mb-2">{plan.name}</h3>
                <div className="flex items-baseline justify-center gap-1 mb-3">
                  <span className="text-4xl font-bold">{plan.price}</span>
                  <span className="text-muted-foreground">one-time</span>
                </div>
                <p className="text-sm text-muted-foreground">{plan.description}</p>
              </div>

              {/* Features */}
              <ul className="space-y-3 mb-8">
                {plan.features.map((feature) => (
                  <li key={feature} className="flex items-start gap-3">
                    <div className="w-5 h-5 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0 mt-0.5">
                      <Check className="w-3 h-3 text-primary" />
                    </div>
                    <span className="text-sm">{feature}</span>
                  </li>
                ))}
              </ul>

              {/* CTA Button */}
              <a href={plan.paypalUrl} target="_blank" rel="noopener noreferrer" className="block">
                <Button 
                  className={`w-full ${plan.highlighted ? 'zxwy-btn-primary' : 'zxwy-btn-secondary'}`}
                >
                  Get {plan.name}
                  <ExternalLink className="w-4 h-4 ml-2" />
                </Button>
              </a>
            </div>
          ))}
        </div>

        {/* Mobile Carousel */}
        <div className="lg:hidden relative h-[500px] animate-on-scroll delay-1">
          {/* Cards */}
          <div className="absolute inset-0 flex items-center justify-center">
            {plans.map((plan, index) => (
              <div
                key={plan.id}
                className={`
                  absolute w-full max-w-sm bg-card border rounded-2xl p-6
                  transition-all duration-300 cursor-pointer
                  ${plan.highlighted ? 'border-primary' : 'border-border'}
                `}
                style={getCardStyle(index)}
                onClick={() => setActiveIndex(index)}
              >
                {/* Plan Header */}
                <div className="text-center mb-6">
                  <div className="w-14 h-14 rounded-xl bg-primary/10 mx-auto mb-3 flex items-center justify-center">
                    <plan.icon className="w-7 h-7 text-primary" />
                  </div>
                  <h3 className="text-xl font-bold mb-1">{plan.name}</h3>
                  <div className="flex items-baseline justify-center gap-1 mb-2">
                    <span className="text-3xl font-bold">{plan.price}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">{plan.description}</p>
                </div>

                {/* Features */}
                <ul className="space-y-2 mb-6">
                  {plan.features.slice(0, 4).map((feature) => (
                    <li key={feature} className="flex items-start gap-2">
                      <Check className="w-4 h-4 text-primary flex-shrink-0 mt-0.5" />
                      <span className="text-sm">{feature}</span>
                    </li>
                  ))}
                  {plan.features.length > 4 && (
                    <li className="text-sm text-muted-foreground pl-6">
                      +{plan.features.length - 4} more features
                    </li>
                  )}
                </ul>

                {/* CTA */}
                <a href={plan.paypalUrl} target="_blank" rel="noopener noreferrer" className="block">
                  <Button className="w-full zxwy-btn-primary">
                    Get {plan.name}
                  </Button>
                </a>
              </div>
            ))}
          </div>

          {/* Navigation */}
          <div className="absolute bottom-0 left-0 right-0 flex items-center justify-center gap-4">
            <button
              onClick={() => navigate('prev')}
              className="w-10 h-10 rounded-full bg-card border border-border flex items-center justify-center hover:border-primary/50 transition-colors"
            >
              <ChevronLeft className="w-5 h-5" />
            </button>
            
            {/* Dots */}
            <div className="flex gap-2">
              {plans.map((_, index) => (
                <button
                  key={index}
                  onClick={() => setActiveIndex(index)}
                  className={`
                    w-2 h-2 rounded-full transition-all duration-300
                    ${index === activeIndex ? 'w-6 bg-primary' : 'bg-muted-foreground/30'}
                  `}
                />
              ))}
            </div>
            
            <button
              onClick={() => navigate('next')}
              className="w-10 h-10 rounded-full bg-card border border-border flex items-center justify-center hover:border-primary/50 transition-colors"
            >
              <ChevronRight className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Support Note */}
        <div className="text-center mt-12 animate-on-scroll delay-2">
          <p className="text-muted-foreground">
            Have questions about which plan to choose?{' '}
            <a 
              href="https://discord.gg/UQmBUXct" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-primary hover:underline"
            >
              Contact us on Discord
            </a>
          </p>
        </div>
      </div>
    </section>
  );
}
