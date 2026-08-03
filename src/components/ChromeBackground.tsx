import { useRef } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Environment, MeshTransmissionMaterial, Float, Sparkles } from '@react-three/drei';
import * as THREE from 'three';

function Blob() {
  const mesh = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    if (mesh.current) {
      mesh.current.rotation.x = Math.sin(state.clock.elapsedTime / 4) * 0.5;
      mesh.current.rotation.y += 0.005;
    }
  });

  return (
    <Float speed={2} rotationIntensity={1.5} floatIntensity={2}>
      <mesh ref={mesh} scale={1.8}>
        {/* Abstract technological shape */}
        <torusKnotGeometry args={[1, 0.4, 256, 64]} />
        <MeshTransmissionMaterial
          backside
          backsideThickness={5}
          thickness={2}
          roughness={0}
          transmission={1}
          ior={1.2}
          chromaticAberration={0.4}
          anisotropy={0.3}
          color="#ffffff"
          envMapIntensity={2}
        />
      </mesh>
    </Float>
  );
}

export function ChromeBackground() {
  return (
    <div className="fixed inset-0 z-0 pointer-events-none opacity-20 mix-blend-screen">
      <Canvas camera={{ position: [0, 0, 8], fov: 45 }}>
        <ambientLight intensity={0.5} />
        <directionalLight position={[10, 10, 5]} intensity={2} color="#36FE35" />
        <directionalLight position={[-10, -10, -5]} intensity={1} color="#ffffff" />
        <directionalLight position={[0, -10, 0]} intensity={1} color="#36FE35" />
        <Environment preset="city" />
        <Blob />
        <Sparkles count={50} scale={10} size={2} speed={0.2} opacity={0.2} color="#36FE35" />
      </Canvas>
    </div>
  );
}
