import type { Transition } from 'framer-motion';

type CubicBezier = [number, number, number, number];

export const baseEase: CubicBezier = [0.25, 0.1, 0.25, 1];

export const baseTransition: Transition = {
  duration: 0.22,
  ease: baseEase
};

export const hoverTransition: Transition = {
  duration: 0.2,
  ease: baseEase
};
