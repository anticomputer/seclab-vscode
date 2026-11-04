# product.json transform. Input: upstream product.json. $ov[0]: overrides.json.
# Applied as data on every build so upstream bumps never conflict.

# Deep-merge our overrides (objects merge key-by-key; our values win).
. * $ov[0]

# Settings Sync off: without a store the sync service is unavailable.
| del(."configurationSync.store")
| del(."editSessions.store")

# Fail the build if any invariant does not hold after the merge.
| if (.extensionEnabledApiProposals["seclab.tab-manager"] | index("resolvers")) == null
    then error("invariant: seclab.tab-manager must be granted the resolvers proposal") else . end
| if ([.extensionKind[]] | all(. == ["workspace"])) | not
    then error("invariant: extensionKind overrides may only force [\"workspace\"]") else . end
| if has("configurationSync.store") then error("invariant: Settings Sync store must be absent") else . end
| if (.extensionsGallery.serviceUrl | startswith("https://open-vsx.org/")) | not
    then error("invariant: gallery must be Open VSX") else . end
