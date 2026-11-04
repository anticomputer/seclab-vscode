# RPC attack-surface inventory

**Generated. Do not edit by hand.** Regenerate with
`rpc-filter/tools/run.sh` (see [AGENTS.md](../AGENTS.md)).

| | |
|---|---|
| Upstream | `microsoft/vscode@881999100739` |
| SHA source | fallback-constant |
| Schema | 1 |

Every surface here is a way code inside a tab can make the **trusted**
side act, or make it interpret tab-supplied data with authority. The
filter is default-deny: anything in this inventory without a verdict in
`rpc-filter/policy/policy.json` fails the drift check and fails the build.

## (a) `MainThread*` RPC, extension host to workbench

89 services, 546 distinct methods.

`RPCProtocol._doInvokeHandler` resolves the target with
`actor[methodName]` and only checks that it is a function, so the
callable surface is **every `$` method on the customer class**, not just
the `MainThread*Shape` interface. 2 methods are callable without being
declared in a Shape.

The wire key is the string `sid` passed to `createProxyIdentifier`, which
is not always the `MainContext` property name. Policy keys on `sid`.
The numeric `nid` is assigned by module load order and must never be a key.

| Service (`MainContext` key) | Wire `sid` | Customer class | Methods | Undeclared |
|---|---|---|---:|---:|
| [`MainThreadAgentEditorComments`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4260) | `MainThreadAgentEditorComments` | [`MainThreadAgentEditorComments`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadAgentEditorComments.ts#L22) | 4 | 0 |
| [`MainThreadAiEmbeddingVector`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4306) | `MainThreadAiEmbeddingVector` | [`MainThreadAiEmbeddingVector`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadAiEmbeddingVector.ts#L12) | 2 | 0 |
| [`MainThreadAiRelatedInformation`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4305) | `MainThreadAiRelatedInformation` | [`MainThreadAiRelatedInformation`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadAiRelatedInformation.ts#L13) | 3 | 0 |
| [`MainThreadAiSettingsSearch`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4310) | `MainThreadAiSettingsSearch` | [`MainThreadAiSettingsSearch`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadAiSettingsSearch.ts#L11) | 3 | 0 |
| [`MainThreadAuthentication`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4228) | `MainThreadAuthentication` | [`MainThreadAuthentication`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadAuthentication.ts#L131) | 15 | 0 |
| [`MainThreadBrowserTunnelProxy`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4299) | `MainThreadBrowserTunnelProxy` | [`MainThreadBrowserTunnelProxy`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadBrowserTunnelProxy.ts#L21) | 5 | 0 |
| [`MainThreadBrowsers`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4316) | `MainThreadBrowsers` | [`MainThreadBrowsers`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadBrowsers.ts#L20) | 5 | 0 |
| [`MainThreadBulkEdits`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4229) | `MainThreadBulkEdits` | [`MainThreadBulkEdits`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadBulkEdits.ts#L19) | 1 | 0 |
| [`MainThreadChatAgents2`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4232) | `MainThreadChatAgents2` | [`MainThreadChatAgents2`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadChatAgents2.ts#L103) | 22 | 2 |
| [`MainThreadChatArtifactIntegrations`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4301) | `MainThreadChatArtifactIntegrations` | [`MainThreadChatArtifactIntegrations`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadChatArtifactIntegrations.ts#L22) | 9 | 0 |
| [`MainThreadChatContext`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4314) | `MainThreadChatContext` | [`MainThreadChatContext`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadChatContext.ts#L28) | 6 | 0 |
| [`MainThreadChatDebug`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4315) | `MainThreadChatDebug` | [`MainThreadChatDebug`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadChatDebug.ts#L15) | 5 | 0 |
| [`MainThreadChatInputNotification`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4309) | `MainThreadChatInputNotification` | [`MainThreadChatInputNotification`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadChatInputNotification.ts#L11) | 2 | 0 |
| [`MainThreadChatOutputRenderer`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4313) | `MainThreadChatOutputRenderer` | [`MainThreadChatOutputRenderer`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadChatOutputRenderer.ts#L16) | 2 | 0 |
| [`MainThreadChatQuota`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4308) | `MainThreadChatQuota` | [`MainThreadChatQuota`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadChatQuota.ts#L11) | 1 | 0 |
| [`MainThreadChatSessions`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4312) | `MainThreadChatSessions` | [`MainThreadChatSessions`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadChatSessions.ts#L680) | 14 | 0 |
| [`MainThreadChatStatus`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4307) | `MainThreadChatStatus` | [`MainThreadChatStatus`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadChatStatus.ts#L11) | 2 | 0 |
| [`MainThreadClipboard`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4236) | `MainThreadClipboard` | [`MainThreadClipboard`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadClipboard.ts#L11) | 2 | 0 |
| [`MainThreadCodeMapper`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4233) | `MainThreadCodeMapper` | [`MainThreadChatCodemapper`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadChatCodeMapper.ts#L14) | 3 | 0 |
| [`MainThreadCommands`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4237) | `MainThreadCommands` | [`MainThreadCommands`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadCommands.ts#L16) | 5 | 0 |
| [`MainThreadComments`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4238) | `MainThreadComments` | [`MainThreadComments`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadComments.ts#L540) | 9 | 0 |
| [`MainThreadConfiguration`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4239) | `MainThreadConfiguration` | [`MainThreadConfiguration`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadConfiguration.ts#L16) | 2 | 0 |
| [`MainThreadConsole`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4240) | `MainThreadConsole` | [`MainThreadConsole`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadConsole.ts#L14) | 1 | 0 |
| [`MainThreadCustomEditors`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4274) | `MainThreadCustomEditors` | [`MainThreadCustomEditors`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadCustomEditors.ts#L82) | 6 | 0 |
| [`MainThreadDataChannels`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4311) | `MainThreadDataChannels` | [`MainThreadDataChannels`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadDataChannels.ts#L16) | 5 | 0 |
| [`MainThreadDebugService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4241) | `MainThreadDebugService` | [`MainThreadDebugService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadDebugService.ts#L24) | 21 | 0 |
| [`MainThreadDecorations`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4242) | `MainThreadDecorations` | [`MainThreadDecorations`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadDecorations.ts#L70) | 3 | 0 |
| [`MainThreadDiagnostics`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4243) | `MainThreadDiagnostics` | [`MainThreadDiagnostics`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadDiagnostics.ts#L14) | 2 | 0 |
| [`MainThreadDialogs`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4244) | `MainThreadDiaglogs` **(differs)** | [`MainThreadDialogs`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadDialogs.ts#L11) | 2 | 0 |
| [`MainThreadDocumentContentProviders`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4246) | `MainThreadDocumentContentProviders` | [`MainThreadDocumentContentProviders`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadDocumentContentProviders.ts#L20) | 3 | 0 |
| [`MainThreadDocumentDiff`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4261) | `MainThreadDocumentDiff` | [`MainThreadDocumentDiff`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadDocumentDiff.ts#L12) | 1 | 0 |
| [`MainThreadDocuments`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4245) | `MainThreadDocuments` | [`MainThreadDocuments`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadDocuments.ts#L126) | 3 | 0 |
| [`MainThreadDownloadService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4252) | `MainThreadDownloadService` | [`MainThreadDownloadService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadDownloadService.ts#L12) | 1 | 0 |
| [`MainThreadEditorInsets`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4248) | `MainThreadEditorInsets` | [`MainThreadEditorInsets`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadCodeInsets.ts#L55) | 5 | 0 |
| [`MainThreadEditorTabs`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4249) | `MainThreadEditorTabs` | [`MainThreadEditorTabs`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadEditorTabs.ts#L38) | 3 | 0 |
| [`MainThreadEmbeddings`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4231) | `MainThreadEmbeddings` | [`MainThreadEmbeddings`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadEmbeddings.ts#L74) | 3 | 0 |
| [`MainThreadErrors`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4250) | `MainThreadErrors` | [`MainThreadErrors`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadErrors.ts#L10) | 1 | 0 |
| [`MainThreadExtensionService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4281) | `MainThreadExtensionService` | [`MainThreadExtensionService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadExtensionService.ts#L33) | 8 | 0 |
| [`MainThreadFileSystem`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4279) | `MainThreadFileSystem` | [`MainThreadFileSystem`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadFileSystem.ts#L15) | 12 | 0 |
| [`MainThreadFileSystemEventService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4280) | `MainThreadFileSystemEventService` | [`MainThreadFileSystemEventService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadFileSystemEventService.ts#L28) | 2 | 0 |
| [`MainThreadGitExtension`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4235) | `MainThreadGitExtension` | [`MainThreadGitExtensionService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadGitExtensionService.ts#L70) | 1 | 0 |
| [`MainThreadGitHub`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4288) | `MainThreadGitHub` | [`MainThreadGitHub`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadGitHub.ts#L51) | 5 | 0 |
| [`MainThreadInteractive`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4295) | `MainThreadInteractive` | [`MainThreadInteractive`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadInteractive.ts#L12) | 0 | 0 |
| [`MainThreadLabelService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4289) | `MainThreadLabelService` | [`MainThreadLabelService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadLabelService.ts#L11) | 2 | 0 |
| [`MainThreadLanguageFeatures`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4253) | `MainThreadLanguageFeatures` | [`MainThreadLanguageFeatures`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadLanguageFeatures.ts#L45) | 47 | 0 |
| [`MainThreadLanguageModelTools`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4234) | `MainThreadChatSkills` **(differs)** | [`MainThreadLanguageModelTools`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadLanguageModelTools.ts#L20) | 7 | 0 |
| [`MainThreadLanguageModels`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4230) | `MainThreadLanguageModels` | [`MainThreadLanguageModels`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadLanguageModels.ts#L51) | 12 | 0 |
| [`MainThreadLanguages`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4254) | `MainThreadLanguages` | [`MainThreadLanguages`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadLanguages.ts#L22) | 5 | 0 |
| [`MainThreadLocalization`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4303) | `MainThreadLocalizationShape` **(differs)** | [`MainThreadLocalization`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadLocalization.ts#L13) | 2 | 0 |
| [`MainThreadLogger`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4255) | `MainThreadLogger` | [`MainThreadLoggerService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadLogService.ts#L15) | 6 | 0 |
| [`MainThreadManagedSockets`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4298) | `MainThreadManagedSockets` | [`MainThreadManagedSockets`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadManagedSockets.ts#L16) | 5 | 0 |
| [`MainThreadMcp`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4304) | `MainThreadMcpShape` **(differs)** | [`MainThreadMcp`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadMcp.ts#L41) | 11 | 0 |
| [`MainThreadMessageService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4256) | `MainThreadMessageService` | [`MainThreadMessageService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadMessageService.ts#L20) | 1 | 0 |
| [`MainThreadMeteredConnection`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4268) | `MainThreadMeteredConnection` | [`MainThreadMeteredConnection`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadMeteredConnection.ts#L11) | 0 | 0 |
| [`MainThreadNotebook`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4290) | `MainThreadNotebook` | [`MainThreadNotebooks`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadNotebook.ts#L29) | 5 | 0 |
| [`MainThreadNotebookDocuments`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4291) | `MainThreadNotebookDocumentsShape` **(differs)** | [`MainThreadNotebookDocuments`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadNotebookDocuments.ts#L20) | 3 | 0 |
| [`MainThreadNotebookEditors`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4292) | `MainThreadNotebookEditorsShape` **(differs)** | [`MainThreadNotebookEditors`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadNotebookEditors.ts#L32) | 3 | 0 |
| [`MainThreadNotebookKernels`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4293) | `MainThreadNotebookKernels` | [`MainThreadNotebookKernels`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadNotebookKernels.ts#L111) | 18 | 0 |
| [`MainThreadNotebookRenderers`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4294) | `MainThreadNotebookRenderers` | [`MainThreadNotebookRenderers`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadNotebookRenderers.ts#L11) | 1 | 0 |
| [`MainThreadOutputService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4257) | `MainThreadOutputService` | [`MainThreadOutputService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadOutputService.ts#L19) | 5 | 0 |
| [`MainThreadPower`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4287) | `MainThreadPower` | [`MainThreadPower`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadPower.ts#L11) | 7 | 0 |
| [`MainThreadProfileContentHandlers`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4277) | `MainThreadProfileContentHandlers` | [`MainThreadProfileContentHandlers`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadProfileContentHandlers.ts#L14) | 2 | 0 |
| [`MainThreadProgress`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4258) | `MainThreadProgress` | [`MainThreadProgress`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadProgress.ts#L17) | 3 | 0 |
| [`MainThreadQuickDiff`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4259) | `MainThreadQuickDiff` | [`MainThreadQuickDiff`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadQuickDiff.ts#L14) | 4 | 0 |
| [`MainThreadQuickOpen`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4262) | `MainThreadQuickOpen` | [`MainThreadQuickOpen`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadQuickOpen.ts#L28) | 6 | 0 |
| [`MainThreadSCM`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4282) | `MainThreadSCM` | [`MainThreadSCM`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadSCM.ts#L614) | 17 | 0 |
| [`MainThreadSearch`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4283) | `MainThreadSearch` | [`MainThreadSearch`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadSearch.ts#L19) | 8 | 0 |
| [`MainThreadSecretState`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4264) | `MainThreadSecretState` | [`MainThreadSecretState`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadSecretState.ts#L14) | 4 | 0 |
| [`MainThreadShare`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4284) | `MainThreadShare` | [`MainThreadShare`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadShare.ts#L13) | 2 | 0 |
| [`MainThreadSpeech`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4266) | `MainThreadSpeechProvider` **(differs)** | [`MainThreadSpeech`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadSpeech.ts#L26) | 6 | 0 |
| [`MainThreadStatusBar`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4263) | `MainThreadStatusBar` | [`MainThreadStatusBar`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadStatusBar.ts#L18) | 2 | 0 |
| [`MainThreadStorage`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4265) | `MainThreadStorage` | [`MainThreadStorage`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadStorage.ts#L16) | 3 | 0 |
| [`MainThreadTask`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4285) | `MainThreadTask` | [`MainThreadTask`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadTask.ts#L454) | 10 | 0 |
| [`MainThreadTelemetry`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4267) | `MainThreadTelemetry` | [`MainThreadTelemetry`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadTelemetry.ts#L18) | 1 | 0 |
| [`MainThreadTerminalService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4269) | `MainThreadTerminalService` | [`MainThreadTerminalService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadTerminalService.ts#L35) | 23 | 0 |
| [`MainThreadTerminalShellIntegration`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4270) | `MainThreadTerminalShellIntegration` | [`MainThreadTerminalShellIntegration`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadTerminalShellIntegration.ts#L16) | 1 | 0 |
| [`MainThreadTesting`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4302) | `MainThreadTesting` | [`MainThreadTesting`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadTesting.ts#L25) | 21 | 0 |
| [`MainThreadTextEditors`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4247) | `MainThreadTextEditors` | [`MainThreadTextEditors`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadEditors.ts#L46) | 13 | 0 |
| [`MainThreadTheming`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4296) | `MainThreadTheming` | [`MainThreadTheming`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadTheming.ts#L11) | 0 | 0 |
| [`MainThreadTimeline`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4300) | `MainThreadTimeline` | [`MainThreadTimeline`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadTimeline.ts#L16) | 6 | 0 |
| [`MainThreadTreeViews`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4251) | `MainThreadTreeViews` | [`MainThreadTreeViews`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadTreeViews.ts#L27) | 9 | 0 |
| [`MainThreadTunnelService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4297) | `MainThreadTunnelService` | [`MainThreadTunnelService`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadTunnelService.ts#L24) | 11 | 0 |
| [`MainThreadUriOpeners`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4276) | `MainThreadUriOpeners` | [`MainThreadUriOpeners`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadUriOpeners.ts#L31) | 2 | 0 |
| [`MainThreadUrls`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4275) | `MainThreadUrls` | [`MainThreadUrls`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadUrls.ts#L34) | 3 | 0 |
| [`MainThreadWebviewPanels`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4272) | `MainThreadWebviewPanels` | [`MainThreadWebviewPanels`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadWebviewPanels.ts#L81) | 7 | 0 |
| [`MainThreadWebviewViews`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4273) | `MainThreadWebviewViews` | _none found_ | 6 | 0 |
| [`MainThreadWebviews`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4271) | `MainThreadWebviews` | [`MainThreadWebviews`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadWebviews.ts#L22) | 3 | 0 |
| [`MainThreadWindow`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4286) | `MainThreadWindow` | [`MainThreadWindow`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadWindow.ts#L16) | 3 | 0 |
| [`MainThreadWorkspace`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4278) | `MainThreadWorkspace` | [`MainThreadWorkspace`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadWorkspace.ts#L34) | 20 | 0 |

### Services whose wire `sid` differs from the property name

A policy keyed on the property name would never match these, and the
call would fall through to whatever the default is. With default-deny
that is a breakage; with any allow-by-default it is a silent bypass.

- `MainContext.MainThreadDialogs` travels as `'MainThreadDiaglogs'` — [protocol](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4244)
- `MainContext.MainThreadLanguageModelTools` travels as `'MainThreadChatSkills'` — [protocol](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4234)
- `MainContext.MainThreadLocalization` travels as `'MainThreadLocalizationShape'` — [protocol](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4303)
- `MainContext.MainThreadMcp` travels as `'MainThreadMcpShape'` — [protocol](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4304)
- `MainContext.MainThreadNotebookDocuments` travels as `'MainThreadNotebookDocumentsShape'` — [protocol](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4291)
- `MainContext.MainThreadNotebookEditors` travels as `'MainThreadNotebookEditorsShape'` — [protocol](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4292)
- `MainContext.MainThreadSpeech` travels as `'MainThreadSpeechProvider'` — [protocol](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/common/extHost.protocol.ts#L4266)

### Callable but not declared in the Shape interface

These exist on the registered instance and are therefore reachable
over RPC. Reviewing only the `.protocol.ts` interfaces misses them.

- **MainThreadChatAgents2** (`src/vs/workbench/api/browser/mainThreadChatAgents2.ts`): `$handleProgressChunk`, `$handleAnchorResolve`

## (b) Command registry reachable via `$executeCommand`

2792 commands found. `$executeCommand` takes the id from the caller, so
the whole registry is reachable from a tab.

| Category | Commands |
|---|---:|
| `editor-local` | 388 |
| `extension-management` | 99 |
| `external-and-uri` | 21 |
| `host-filesystem` | 50 |
| `host-process` | 152 |
| `internal-underscore` | 108 |
| `remote-and-tunnel` | 24 |
| `secrets-and-auth` | 10 |
| `settings-and-policy` | 41 |
| `unclassified` | 1881 |
| `window-and-workspace` | 18 |

Categories are a review aid only. They grant nothing: the policy
table still needs a verdict per command id.

### Command ids built from non-literal expressions

150 registrations use a constant or computed id that this static scan
cannot resolve. Default-deny means these are denied until classified,
so the cost is compatibility, not containment.

`ACTION_ID_NEW_CHAT`, `AICustomizationManagementCommands.CreateCanvas`, `AICustomizationManagementCommands.DismissMigrationHint`, `AICustomizationManagementCommands.GenerateDebugReport`, `AICustomizationManagementCommands.OpenEditor`, `AICustomizationManagementCommands.OpenMarketplace`, `AddAreaScreenshotToChatAction.ID`, `AddConsoleLogsToChatAction.ID`, `AddElementCommentToChatAction.ID`, `AddElementToChatAction.ID`, `AddFullPageScreenshotToChatAction.ID`, `AddScreenshotToChatAction.ID`, `BranchChatSessionAction.ID`, `BrowserFindNextAction.ID`, `BrowserFindPreviousAction.ID`, `BrowserViewCommandId.CloseAll`, `BrowserViewCommandId.CloseAllInGroup`, `BrowserViewCommandId.NewTab`, `BrowserViewCommandId.Open`, `BrowserViewCommandId.OpenFile`, `BrowserViewCommandId.OpenOrList`, `BrowserViewCommandId.QuickOpen`, `BuiltinDynamicCompletions.addReferenceCommand`, `CUSTOMIZATION_OVERVIEW_ITEM.id`, `CancelAction.ID`, `CancelEdit.ID`, `CancelSnoozeInlineCompletion.ID`, `ChangeChatModelAction.ID`, `ChatSetupSignInTitleBarAction.ID`, `ClearAgentBrowserStorageAction.ID`, `ClearEphemeralBrowserStorageAction.ID`, `ClearGlobalBrowserStorageAction.ID`, `ClearWorkspaceBrowserStorageAction.ID`, `Constants.SearchCommandIds.AddCursorsAtSearchResults`, `Constants.SearchCommandIds.CancelSearchActionId`, `Constants.SearchCommandIds.ClearSearchHistoryCommandId`, `Constants.SearchCommandIds.ClearSearchResultsActionId`, `Constants.SearchCommandIds.CloseReplaceWidgetActionId`, `Constants.SearchCommandIds.CollapseSearchResultsActionId`, `Constants.SearchCommandIds.CopyAllCommandId`

Full list in `inventory.json`.

## (c) Channels the client serves to the server

The REH server process runs **inside the tab**, so it is hostile. These
channels are called by the server over the remote connection and never
pass through `RPCProtocol`, so a filter scoped to `MainThread*` does not
see them.

2 client-served channels, 20 server-initiated callbacks.

### `McpGatewayToolBrokerChannelName` → `McpGatewayToolBrokerChannel`

- Registered: [`src/vs/workbench/contrib/mcp/browser/mcpGatewayToolBrokerContribution.ts:16`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/contrib/mcp/browser/mcpGatewayToolBrokerContribution.ts#L16)
- Implementation: [`McpGatewayToolBrokerChannel`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/contrib/mcp/common/mcpGatewayToolBrokerChannel.ts#L32)
- Methods: `callToolForServer`, `listResourceTemplatesForServer`, `listResourcesForServer`, `listServers`, `listToolsForServer`, `onDidChangeResources`, `onDidChangeServers`, `onDidChangeTools`, `readResourceForServer`

### `download` → `DownloadServiceChannel`

- Registered: [`src/vs/workbench/contrib/remote/common/remote.contribution.ts:77`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/contrib/remote/common/remote.contribution.ts#L77)
- Implementation: [`DownloadServiceChannel`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/platform/download/common/downloadIpc.ts#L9)
- Methods: `download`
- **Revives a caller-supplied URI**: the server chooses the URI, so this reads and writes wherever the trusted side can.

### Server-initiated callbacks the client acts on

| Effect | Site |
|---|---|
| opens an external URI for the server | [`src/vs/platform/browserView/common/browserView.ts:533`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/platform/browserView/common/browserView.ts#L533) |
| opens an external URI for the server | [`src/vs/platform/browserView/electron-main/browserView.ts:113`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/platform/browserView/electron-main/browserView.ts#L113) |
| opens an external URI for the server | [`src/vs/platform/browserView/electron-main/browserViewMainService.ts:524`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/platform/browserView/electron-main/browserViewMainService.ts#L524) |
| opens an external URI for the server | [`src/vs/workbench/api/browser/mainThreadCLICommands.ts:25`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadCLICommands.ts#L25) |
| opens a window or folder for the server | [`src/vs/workbench/api/browser/mainThreadCLICommands.ts:30`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadCLICommands.ts#L30) |
| reports host status to the server | [`src/vs/workbench/api/browser/mainThreadCLICommands.ts:38`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadCLICommands.ts#L38) |
| installs or manages extensions for the server | [`src/vs/workbench/api/browser/mainThreadCLICommands.ts:50`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/browser/mainThreadCLICommands.ts#L50) |
| opens a window or folder for the server | [`src/vs/workbench/api/node/extHostCLIServer.ts:151`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/node/extHostCLIServer.ts#L151) |
| opens an external URI for the server | [`src/vs/workbench/api/node/extHostCLIServer.ts:161`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/node/extHostCLIServer.ts#L161) |
| installs or manages extensions for the server | [`src/vs/workbench/api/node/extHostCLIServer.ts:173`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/node/extHostCLIServer.ts#L173) |
| reports host status to the server | [`src/vs/workbench/api/node/extHostCLIServer.ts:177`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/api/node/extHostCLIServer.ts#L177) |
| opens an external URI for the server | [`src/vs/workbench/contrib/browserView/common/browserView.ts:409`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/contrib/browserView/common/browserView.ts#L409) |
| opens an external URI for the server | [`src/vs/workbench/contrib/canvases/electron-browser/canvasView.ts:375`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/contrib/canvases/electron-browser/canvasView.ts#L375) |
| opens a window or folder for the server | [`src/vs/workbench/contrib/terminal/browser/remoteTerminalBackend.ts:99`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/contrib/terminal/browser/remoteTerminalBackend.ts#L99) |
| opens an external URI for the server | [`src/vs/workbench/contrib/terminal/browser/remoteTerminalBackend.ts:99`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/contrib/terminal/browser/remoteTerminalBackend.ts#L99) |
| installs or manages extensions for the server | [`src/vs/workbench/contrib/terminal/browser/remoteTerminalBackend.ts:99`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/contrib/terminal/browser/remoteTerminalBackend.ts#L99) |
| reports host status to the server | [`src/vs/workbench/contrib/terminal/browser/remoteTerminalBackend.ts:99`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/contrib/terminal/browser/remoteTerminalBackend.ts#L99) |
| executes a command chosen by the server | [`src/vs/workbench/contrib/terminal/browser/remoteTerminalBackend.ts:100`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/contrib/terminal/browser/remoteTerminalBackend.ts#L100) |
| executes a command chosen by the server | [`src/vs/workbench/contrib/terminal/common/remote/remoteTerminalChannel.ts:91`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/contrib/terminal/common/remote/remoteTerminalChannel.ts#L91) |
| executes a command chosen by the server | [`src/vs/workbench/contrib/terminal/common/remote/terminal.ts:52`](https://github.com/microsoft/vscode/blob/881999100739fef36236fe0b93fedc9b730f94a9/src/vs/workbench/contrib/terminal/common/remote/terminal.ts#L52) |

## (d) Tab-supplied data the trusted side interprets with authority

Not calls: values that start in a tab and are parsed and acted on by the
trusted side. 15 sink classes over 475 sites.

| Surface | Authority it confers | Sites |
|---|---|---:|
| `as-external-uri` | asExternalUri can mint a host-reachable URI or tunnel for the tab | 4 |
| `clipboard` | clipboard read returns whatever the user copied, often a credential | 18 |
| `command-uri-in-markdown` | a `command:` URI in tab-authored markdown runs a command on the trusted side | 134 |
| `extension-identity-argument` | an extension identity supplied as an RPC argument drives a trust decision | 5 |
| `markdown-string-trust` | MarkdownString.isTrusted decides whether embedded command links execute | 90 |
| `mcp-server-definition` | MCP server definitions from config carry secret inputs and env | 59 |
| `open-external` | a URI chosen by the tab is handed to the host OS opener | 17 |
| `proxy-and-kerberos-auth` | proxy and Kerberos credentials are returned to the caller | 3 |
| `quick-input-password` | a password QuickInput captures a real user secret on the trusted side | 4 |
| `terminal-link-opener` | links detected in tab terminal output are opened by the trusted side | 8 |
| `terminal-osc-sequence` | OSC/escape sequences written by the tab are parsed by the trusted terminal UI | 13 |
| `tunnel-and-port-forward` | the tab asks the trusted side to open or forward a port | 22 |
| `uri-handler` | vscode:// callbacks are routed into extensions and can carry OAuth codes | 18 |
| `webview-content` | tab-authored HTML renders in the trusted renderer and can fetch any origin | 28 |
| `workspace-configuration` | workspace settings read from the tab change trusted-side behaviour | 52 |

Representative sites, with permalinks, are in `inventory.json`.

### Our own components reachable from a tab

| Component | Role | Status |
|---|---|---|
| `seclab-tabd` | tab supervisor JSON-RPC over stdio; issues the per-tab identity | TODO (not built yet) |
| `broker` | per-tab mitmproxy broker; the only egress and the sentinel swap point | TODO (not built yet) |
