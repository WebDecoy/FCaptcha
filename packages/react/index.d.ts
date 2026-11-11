import type { CSSProperties, ReactElement } from 'react';

export interface FCaptchaProps {
  siteKey: string;
  onVerify?: (token: string) => void;
  onExpire?: () => void;
  onError?: (error: unknown) => void;
  scriptSrc?: string;
  serverUrl?: string;
  theme?: 'light' | 'dark';
  size?: 'normal';
  lang?: string;
  className?: string;
  style?: CSSProperties;
}

export function FCaptcha(props: FCaptchaProps): ReactElement;
