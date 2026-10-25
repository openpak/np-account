Copy of the account core generated gRPC stubs and `.proto` sources.
Refresh from `platforms/core/infra/account/proto/openpak/account/v1` at the workspace
root. The proto options retain the core source package; use protoc Go import
mappings to target `openpak/np-common/accountpb` when regenerating locally.
Consumers vendor this module and need no account-core checkout during builds.
