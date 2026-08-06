/// <reference types="vite/client" />

export {}

declare global {
  interface Window {
    /** Injected by the backend at runtime from the APP_TITLE env var (see Host/Program.cs). */
    __APP_TITLE__?: string
  }
}
