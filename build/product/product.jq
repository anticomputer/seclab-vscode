# product.json transform. Input: upstream product.json.
#   $ov[0]: build/product/overrides.json
#   $ui[0]: { "<publisher>.<name>": <declared extensionKind> } for upstream BUILT-IN
#           extensions whose manifest prefers "ui" (generated from the pinned source by
#           build/prepare.sh, so it tracks upstream automatically).
# Applied as data on every build so upstream bumps never conflict.

# Deep-merge our overrides (objects merge key-by-key; our values win).
. * $ov[0]

# Every extension runs in the tab ("workspace") unless listed: first-party built-ins that
# declare "ui" keep their declared kind; everything else (any marketplace extension, ui or
# not) is forced into the tab. Needs patches/0002 ('*' default in extensionKind).
| .extensionKind = ($ui[0] + (.extensionKind // {}) + { "*": ["workspace", "-web"] })

# Settings Sync off: without a store the sync service is unavailable.
| del(."configurationSync.store")
| del(."editSessions.store")

# Fail the build if any invariant does not hold after the merge.
| if (.extensionEnabledApiProposals["seclab.tab-manager"] | index("resolvers")) == null
    then error("invariant: seclab.tab-manager must be granted the resolvers proposal") else . end
| if .extensionKind["*"] != ["workspace", "-web"] then error("invariant: default extensionKind must be [\"workspace\", \"-web\"]") else . end
| ($ui[0] | keys) as $allowedUi
| if [.extensionKind | to_entries[] | select(.value | index("ui")) | .key
      | select(. != "seclab.tab-manager" and (. as $k | $allowedUi | index($k) | not))] | length > 0
    then error("invariant: only built-in extensions and the Tab Manager may be ui-kind") else . end
| if [$allowedUi[] | select(startswith("vscode.") | not)] | length > 0
    then error("invariant: generated ui allowlist must only contain vscode.* built-ins") else . end
| if has("configurationSync.store") then error("invariant: Settings Sync store must be absent") else . end
| if .seclabTabRouter != "seclab.tab-manager"
    then error("invariant: local folder opens must route to the Tab Manager (seclabTabRouter, patch 0041)") else . end
| if (.extensionsGallery.serviceUrl | startswith("https://open-vsx.org/")) | not
    then error("invariant: gallery must be Open VSX") else . end
