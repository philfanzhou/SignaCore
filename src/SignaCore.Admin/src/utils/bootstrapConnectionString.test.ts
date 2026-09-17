import { describe, expect, it } from 'vitest'
import {
  buildPostgreSqlConnectionString,
  buildSqliteConnectionString,
  escapeConnectionStringValue,
} from './bootstrapConnectionString'

describe('escapeConnectionStringValue', () => {
  it('wraps plain values in double quotes', () => {
    expect(escapeConnectionStringValue('plain-secret')).toBe('"plain-secret"')
  })

  it('doubles embedded double quotes', () => {
    expect(escapeConnectionStringValue('a"b')).toBe('"a""b"')
  })

  it('keeps semicolons, equals signs, and quotes exactly as typed', () => {
    expect(escapeConnectionStringValue('a;b')).toBe('"a;b"')
    expect(escapeConnectionStringValue('x=y')).toBe('"x=y"')
    expect(escapeConnectionStringValue("'quoted")).toBe('"\'quoted"')
  })

  it('keeps surrounding spaces and non-ASCII input verbatim', () => {
    expect(escapeConnectionStringValue(' padded ')).toBe('" padded "')
    expect(escapeConnectionStringValue('密码;词')).toBe('"密码;词"')
  })

  it('keeps an empty value as an empty quoted string', () => {
    expect(escapeConnectionStringValue('')).toBe('""')
  })
})

describe('buildPostgreSqlConnectionString', () => {
  it('assembles the five fixed keys in order with the default port', () => {
    expect(buildPostgreSqlConnectionString({
      host: 'db',
      port: null,
      database: 'signacore',
      username: 'signacore',
      password: 'secret',
    })).toBe('Host="db";Port=5432;Database="signacore";Username="signacore";Password="secret"')
  })

  it('uses the supplied port and quotes every structured value', () => {
    expect(buildPostgreSqlConnectionString({
      host: 'db.internal',
      port: 5433,
      database: 'signa;core',
      username: 'us"er',
      password: 'a;b=c',
    })).toBe('Host="db.internal";Port=5433;Database="signa;core";Username="us""er";Password="a;b=c"')
  })

  it('keeps a password that would break unquoted concatenation verbatim', () => {
    // Fixed expectation: the backend NpgsqlConnectionStringBuilder round-trip of exactly this
    // shape is pinned by BootstrapConnectionStringRoundTripTests.
    expect(buildPostgreSqlConnectionString({
      host: 'db',
      port: 5432,
      database: 'signacore',
      username: 'signacore',
      password: "a;b'c\"d e",
    })).toBe('Host="db";Port=5432;Database="signacore";Username="signacore";Password="a;b\'c""d e"')
  })
})

describe('buildSqliteConnectionString', () => {
  it('quotes the file path', () => {
    expect(buildSqliteConnectionString('/app/data/signacore.db')).toBe('Data Source="/app/data/signacore.db"')
  })

  it('keeps a path containing separators and quotes exactly as typed', () => {
    expect(buildSqliteConnectionString('/app/a;b\'c.db')).toBe('Data Source="/app/a;b\'c.db"')
  })
})
