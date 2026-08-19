# Integrations

`IntegrationProvider` defines validation and asset synchronization. GitHub is the first provider. Credentials are encrypted with Fernet using a key separate from the database and are never returned by API responses.

The current GitHub connection accepts a scoped token for functional compatibility. A GitHub App/OAuth installation should replace this input flow before broad production rollout. Repository sync registers repository assets inside the authenticated organization only.
