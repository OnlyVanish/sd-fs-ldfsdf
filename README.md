# Crow Android Project — LiveOps 1.4

Standalone Kotlin Android host for the Crow game with a Go release/content server.

- Android source and build instructions: [README_FA.md](README_FA.md)
- Go server installation and operations: [crow-server/README_FA.md](crow-server/README_FA.md)
- Season pack authoring API: [CROW_SEASON_PACKS_FA.md](CROW_SEASON_PACKS_FA.md)
- An upload-ready example pack: `Crow_Season_Template.zip`

The game is stored locally in the app. When online, the updater checks for a signed-by-Android-compatible APK release (SHA-256 + package/version/signing-certificate verification) and downloads remote season packs over HTTPS. Android's package installer still requires user approval. The server can be unavailable without blocking offline play.
