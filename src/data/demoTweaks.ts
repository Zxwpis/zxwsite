import {
  Settings,
  Cpu,
  MemoryStick,
  Trash2,
  MousePointer2,
  Keyboard,
  Zap,
  Network,
  HardDrive,
  Gauge,
  Trophy,
  TerminalSquare,
  Microchip,
  Usb,
  ServerOff,
  Hexagon,
  Maximize2,
  Split,
  Gamepad2,
  Activity,
  ShieldOff,
  Gamepad,
  Layers,
  type LucideIcon,
} from 'lucide-react';

export type DemoTier = 'None' | 'Standard' | 'Max' | 'Ultimate';

export const TIERS: DemoTier[] = ['None', 'Standard', 'Max', 'Ultimate'];

export const TIER_RANK: Record<DemoTier, number> = {
  None: 0,
  Standard: 1,
  Max: 2,
  Ultimate: 3,
};

export const TIER_LABELS: Record<DemoTier, string> = {
  None: 'Unlicensed',
  Standard: 'Standard',
  Max: 'Max',
  Ultimate: 'Ultimate',
};

export interface DemoTweak {
  code: string;
  name: string;
  description: string;
  icon: LucideIcon;
  tier: DemoTier;
}

export const DEMO_TWEAKS: DemoTweak[] = [
  { code: '1', name: 'Windows Tweaks', description: 'General OS tuning: telemetry, scheduling, services', icon: Settings, tier: 'Standard' },
  { code: '2', name: 'GPU Optimization', description: 'Driver-level tweaks, shader cache, scheduler hints', icon: Gauge, tier: 'Max' },
  { code: '3', name: 'CPU Optimization', description: 'Scheduler, affinity, C-states, frequency policy', icon: Cpu, tier: 'Standard' },
  { code: '4', name: 'RAM Optimization', description: 'Memory management, page file, working sets', icon: MemoryStick, tier: 'Standard' },
  { code: '5', name: 'System Cleanup', description: 'Temp files, caches, logs, prefetch', icon: Trash2, tier: 'Standard' },
  { code: '6', name: 'Input Lag Fix', description: 'Mouse/keyboard latency reduction', icon: MousePointer2, tier: 'Standard' },
  { code: '7', name: 'Keyboard / Mouse', description: 'Polling rate, DPI smoothing, raw input', icon: Keyboard, tier: 'Standard' },
  { code: '8', name: 'Power Plan', description: 'High-performance scheme, no throttling', icon: Zap, tier: 'Standard' },
  { code: '9', name: 'Network Optimization', description: 'TCP/IP, DNS, ping reduction', icon: Network, tier: 'Standard' },
  { code: '10', name: 'Storage Optimization', description: 'SSD trim, write cache, lastaccess off', icon: HardDrive, tier: 'Standard' },
  { code: '11', name: 'BCDedit Tweaks', description: 'Boot configuration: timer resolution, hypervisor', icon: TerminalSquare, tier: 'Max' },
  { code: '12', name: 'BIOS Optimization', description: 'Firmware-level recommended settings', icon: Microchip, tier: 'Ultimate' },
  { code: '13', name: 'USB Tweaks', description: 'Polling rate, power management, MSI', icon: Usb, tier: 'Ultimate' },
  { code: '14', name: 'Debloat', description: 'Disable unnecessary services and apps', icon: ServerOff, tier: 'Ultimate' },
  { code: '15', name: 'Game Priority', description: 'CPU/IO priority for system & games', icon: Trophy, tier: 'Max' },
  { code: '16', name: 'DirectX Optimization', description: 'Hardware acceleration, GPU scheduling', icon: Hexagon, tier: 'Ultimate' },
  { code: '17', name: 'Fullscreen Exclusive', description: 'Disable Win10+ borderless override', icon: Maximize2, tier: 'Ultimate' },
  { code: '18', name: 'Interrupt Affinity', description: 'Pin GPU/NIC/USB/Storage IRQs to dedicated CPU cores', icon: Split, tier: 'Ultimate' },
  { code: '19', name: 'Network Adapter Settings', description: 'Tune NIC advanced props: RSS, buffers, flow control', icon: Network, tier: 'Ultimate' },
  { code: '20', name: 'GPU Per-Process Scheduling', description: 'Force High-Performance GPU + VRR per game executable', icon: Gamepad2, tier: 'Ultimate' },
  { code: '21', name: 'Frametime Optimizer', description: 'Targeted frametime & 1% low fix: timer, DPC, GPU scheduler, C-states', icon: Activity, tier: 'Max' },
  { code: '22', name: 'Privacy', description: 'Disable telemetry, ads, location, tracking, UI clutter', icon: ShieldOff, tier: 'Standard' },
  { code: '23', name: 'Game Present FPS Pack', description: 'Game Mode on, DVR/Captures off, FSE defaults, MMCSS boost', icon: Gamepad, tier: 'Max' },
  { code: '24', name: 'HAGS Control', description: 'Hardware-accelerated GPU Scheduling on/off', icon: Layers, tier: 'Max' },
];

export function isDemoTweakAllowed(tweak: DemoTweak, tier: DemoTier): boolean {
  return TIER_RANK[tier] >= TIER_RANK[tweak.tier];
}
