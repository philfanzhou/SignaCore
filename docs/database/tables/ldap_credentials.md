# ldap_credentials

Directory identities bound to SignaCore accounts. Directory profile data is not synchronized into
this table.

## Columns

- id (UUID, primary key)
- account_id
- directory_key / directory_key_normalized
- object_guid
- user_principal_name / user_principal_name_normalized
- sam_account_name / sam_account_name_normalized
- created_at

## Relationships and invariants

- account_id references accounts and cascades on delete.
- Directory key plus object GUID is unique.
- Directory key plus normalized UPN is unique.
- Directory key plus normalized SAM account name is unique.
- Per-application admission is stored separately in app_ldap_accesses.

## Ownership

SignaCore owns all writes to this table. Other services must use the HTTP API rather than direct database access.
