import { useEffect, useRef } from 'react';

export function PixelGrid() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const trailRef = useRef<{ col: number; row: number; opacity: number }[]>([]);
  const lastCellRef = useRef<{ col: number; row: number } | null>(null);
  const lastMousePosRef = useRef<{ x: number; y: number } | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let width = 0;
    let height = 0;
    const cellSize = 28; // Size of each grid square in pixels

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      width = rect.width;
      height = rect.height;
      // Set high-DPI scaling
      const dpr = window.devicePixelRatio || 1;
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      ctx.scale(dpr, dpr);
    };

    resize();
    window.addEventListener('resize', resize);

    // Render loop
    const render = () => {
      ctx.clearRect(0, 0, width, height);

      // 1. Draw the subtle base grid (scrolling-aligned)
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.035)';
      ctx.lineWidth = 1;

      const cols = Math.ceil(width / cellSize);
      const scrollOffset = window.scrollY;
      const gridOffsetY = -(scrollOffset % cellSize);

      ctx.beginPath();
      // Draw vertical lines
      for (let c = 0; c <= cols; c++) {
        const x = c * cellSize;
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
      }
      // Draw horizontal lines offset by current scroll
      for (let y = gridOffsetY; y <= height + cellSize; y += cellSize) {
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
      }
      ctx.stroke();

      // 2. Update and draw trailing active pixels
      const updatedTrail: typeof trailRef.current = [];

      for (const pixel of trailRef.current) {
        pixel.opacity -= 0.015; // Slow decay to match reference trail length
        if (pixel.opacity > 0) {
          updatedTrail.push(pixel);

          const drawY = pixel.row * cellSize - scrollOffset;

          // Only draw if within visible viewport bounds
          if (drawY + cellSize >= 0 && drawY <= height) {
            // Draw the filled cell
            ctx.fillStyle = `rgba(54, 254, 53, ${pixel.opacity * 0.4})`;
            ctx.fillRect(pixel.col * cellSize + 1, drawY + 1, cellSize - 2, cellSize - 2);

            // Highlight border of active pixel
            ctx.strokeStyle = `rgba(255, 255, 255, ${pixel.opacity * 0.25})`;
            ctx.strokeRect(pixel.col * cellSize + 1, drawY + 1, cellSize - 2, cellSize - 2);
          }
        }
      }

      trailRef.current = updatedTrail;
      animationFrameId = requestAnimationFrame(render);
    };

    render();

    // Helper to trigger active cell logic
    const triggerPixelsAt = (x: number, y: number) => {
      const col = Math.floor(x / cellSize);
      const row = Math.floor(y / cellSize);

      // Check if cursor moved to a new page-relative cell
      if (!lastCellRef.current || lastCellRef.current.col !== col || lastCellRef.current.row !== row) {
        lastCellRef.current = { col, row };

        // Add center lit-up cell
        trailRef.current.push({ col, row, opacity: 1.0 });

        // Add adjacent cells with a lower opacity to create a beautiful pixel bloom/fade glow
        const neighbors = [
          { col: col - 1, row, opacity: 0.5 },
          { col: col + 1, row, opacity: 0.5 },
          { col, row: row - 1, opacity: 0.5 },
          { col, row: row + 1, opacity: 0.5 },
          // Diagonal neighbors
          { col: col - 1, row: row - 1, opacity: 0.25 },
          { col: col + 1, row: row - 1, opacity: 0.25 },
          { col: col - 1, row: row + 1, opacity: 0.25 },
          { col: col + 1, row: row + 1, opacity: 0.25 },
        ];

        for (const neighbor of neighbors) {
          if (neighbor.col >= 0 && neighbor.row >= 0) {
            trailRef.current.push(neighbor);
          }
        }
      }
    };

    // Mouse move tracking
    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      lastMousePosRef.current = { x, y };
      triggerPixelsAt(x, y);
    };

    // Scroll tracking to trigger grid squares as content moves under cursor
    const handleScroll = () => {
      if (lastMousePosRef.current) {
        const { x, y } = lastMousePosRef.current;
        triggerPixelsAt(x, y);
      }
    };

    const handleMouseLeave = () => {
      lastCellRef.current = null;
    };

    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('scroll', handleScroll, { passive: true });
    window.addEventListener('mouseleave', handleMouseLeave);

    return () => {
      window.removeEventListener('resize', resize);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('scroll', handleScroll);
      window.removeEventListener('mouseleave', handleMouseLeave);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 w-full h-full pointer-events-none block z-0"
    />
  );
}