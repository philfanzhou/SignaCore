# WeChat Binding: Implementation Status

The feature is implemented. Use this checklist when changing it:

- [ ] Keep the public HTTP contract backward compatible unless a versioned change is approved.
- [ ] Keep bind, login, and refresh admission rules consistent with each other.
- [ ] Add or update unit tests for policy branches.
- [ ] Add database contract coverage for binding conflicts and cascade behavior.
- [ ] Verify logs and errors do not expose secrets, raw OpenId values, or personal data.
- [ ] Update this module documentation and the relevant overview document.

A rename-only change must not rename existing database tables, JSON properties, routes, or JWT claim names.
