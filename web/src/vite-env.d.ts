/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** `VITE_MOCK=1 npm run build`: force the in-browser mock adapter (src/api/mock). */
  readonly VITE_MOCK?: string
  /** `VITE_STATIC=1 npm run build`: the static snapshot edition (relative assets, hash routing, src/api/snapshot transport). */
  readonly VITE_STATIC?: string
}
