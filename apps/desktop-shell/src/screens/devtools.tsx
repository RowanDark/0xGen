import { RouterDevtools } from '@tanstack/router-devtools';

declare const __DEVTOOLS_ENABLED__: boolean;

type Props = Record<string, never>;

export default function Devtools(_: Props) {
  if (!__DEVTOOLS_ENABLED__) {
    return null;
  }

  return <RouterDevtools position="bottom-right" />;
}
