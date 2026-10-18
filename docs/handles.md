# Permanent account handles

Core GetAccount/ListAccounts now carry handle, separate from display_name.
Automatic NP provisioning uses a populated handle verbatim, with exactly one
candidate: a collision is an error, never permission to append a hash. New
sign-in link creation refuses a requested online ID that differs from the core
handle. The core prevents PlayStation subject/public-code drift afterwards.

The reviewed alpha migration updates the existing np link subject and public
code in one core transaction, preserving its link ID. This preserves the PSN
user_id derived from the link; unlinking/relinking would not. Numeric native
account numbers and trophy ownership stay on the existing core account UUID.
No user-facing rename path is introduced. Legacy display derivation exists only
for accounts not yet migrated.

At permanent deletion the core retires the textual NP subject but preserves its
historical link ID. After the 90-day hold, a new owner of the handle receives a
new account/link identity. Future PS4/PS5 services must use this same core handle
contract and should share the PlayStation identity rather than choose a new name.
