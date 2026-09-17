export interface BootstrapProvider {
  provider: string
  serverVersions: string[]
  defaultPort: number | null
  singleInstanceOnly: boolean
}

// The shared installation status entry discloses only the phase, not the provider catalog, so the
// forms offer the same combinations the backend accepts from this fixed list. The first-install
// form and the admin settings panel share this one copy.
export const bootstrapProviderCatalog: BootstrapProvider[] = [
  {
    provider: 'PostgreSQL',
    serverVersions: ['15', '16', '17'],
    defaultPort: 5432,
    singleInstanceOnly: false,
  },
  {
    provider: 'SQLite',
    serverVersions: [],
    defaultPort: null,
    singleInstanceOnly: true,
  },
]
