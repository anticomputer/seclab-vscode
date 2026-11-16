# Which agents can exist in a tab window, and why increment 4 closes increment 3's gap

- **Status:** accepted
- **Date:** 2026-11-16
- **Deciders:** Coordinator (2026-11-16): hold increment 3 unlanded and land it with increment 4, once increment 4's registration constraint closes finding R12-2; no owner acceptance needed, since nothing is deferred past the landing.
- **Related:** [implementation plan](../plans/agentic-implementation.md) increments 3 and 4, [AHP gate review rounds](../security-reviews/20261106-agentic-ahp-gate.md) round 12, [agentic probe runner](20261106-agentic-probe-runner.md)

## Why this record exists

Patch 0018 (increment 3) refuses a chat request in a `seclab+` window unless its session
resolves to that window's own agent-host connection and was registered by it. Its round 2
security review found that this authorises the *session* while the *agent id* that decides
where the request actually executes is chosen separately: from the caller, from a participant
mention parsed out of the request text, or from participant detection. None of those are
constrained by the session resource. Registered as finding R12-2, high, open.

`IChatAgentData` carries an extension id and no connection, so there is no local comparison
0018 could make. The property it needs is not about an individual request at all; it is about
which agents can be registered in a tab window in the first place. That is increment 4's
subject, so the two increments land together rather than shipping a gate whose stated property
is not yet true.

## The inventory

Every non-test site that registers a chat agent in the pinned upstream tree, grouped by who
controls it. Read from the tree at the SHA in `upstream.lock`.

| # | Site | Controlled by | Status in a tab window |
|---|---|---|---|
| 1 | `chat/browser/chatParticipant.contribution.ts:297` | an extension's `chatParticipants` contribution | denied: the RPC filter denies `MainThreadChatAgents2.$register*` |
| 2 | `chat/browser/chatSessions/chatSessions.contribution.ts:876` | an extension's `chatSessions` contribution | denied: same filter rule, same extension-host route |
| 3 | `chat/browser/agentSessions/agentHost/agentHostSessionHandler.ts:2120` | this window's own agent host | allowed, and is the intent |
| 4 | `chat/browser/agentSessions/agentHost/agentHostChatContribution.ts:318` | this window's own agent host | allowed, same connection |
| 5 | `chat/browser/agentSessions/agentHost/agentHostSessionListContribution.ts:148` | this window's own agent host | allowed, same connection |
| 6 | `chat/browser/remoteAgentHost/remoteAgentHostChatContribution.ts:400` | a *remote* agent host the window connects to | **the gap**: not this window's connection, and nothing stops it |

Rows 1 and 2 are the extension-host route, already closed. Rows 3 to 5 are the window's own
gated connection, which is exactly what 0018 allows. Row 6 is the only way an agent belonging
to some other connection enters the window, and it is the one increment 4 removes.

So R12-2 is closed by increment 4 rather than worked around: once row 6 cannot register,
the premise 0018 rests on — that every agent implementation in a tab window belongs to that
window's own gated connection — is established by construction rather than assumed.

## What increment 4 has to remove

The providers behind row 6 are registered in one place,
`chat/browser/remoteAgentHost/remoteAgentHost.contribution.ts`: ten `registerSingleton` calls
(the cloud sandbox services, the Mission Control services, the connection-customization
service and the advertised-authentication resolver) and three workbench contributions. No
other file registers any of them, which is what makes a single, small patch possible.

## Design constraint, and the option rejected

`registerSingleton` runs at module load, before any service exists, so the registration cannot
branch on the window's authority. Three options were considered.

1. **Branch at registration.** Rejected: there is nothing to branch on yet.
2. **Replace each service with a hand-written null class.** Rejected: ten null classes is far
   past the patch-size rule, and each is a separate chance to get an interface subtly wrong.
3. **One wrapper, chosen.** A single registration helper that takes the real class and, when
   constructed, either returns the real service (ordinary windows) or an inert stand-in
   (`seclab+` windows), emitting `seclab.null-provider.registered` as it does so. A
   constructor may return an object, so this preserves the real class's dependency injection
   in the case that still needs it.

The event matters as much as the behaviour: the plan requires every G run to *assert* that
each of these services resolved to the null provider, rather than infer it from the absence of
a connection. Absence of effect is not containment, and a check that cannot fail is not
evidence.

## Both halves are needed, which was checked rather than assumed

The agent registration at row 6 is a method of `RemoteAgentHostContribution`, one of the three
workbench contributions. So withholding those three contributions in a tab window is what
actually closes R12-2, and it is the low-risk half: a contribution that never runs is the same
state upstream is in when the feature is off.

That raised the obvious question of whether the ten services could then be left alone, on the
grounds that only those contributions resolve them. They cannot. Reading the tree for
consumers outside the remote agent-host directory found real ones:
`IMissionControlSharingService` is resolved by the remote-connections toggle and by the tunnel
host contribution, and `IRemoteAgentHostConnectionCustomizationService` by the agent-host
artifact integrations. Nulling the services is therefore not belt-and-braces; it is load
bearing for those consumers, and the plan was right to ask for it.

Stated plainly because it is the kind of premise this project has been caught on before: "only
the contributions use these services" is false, and had it been assumed rather than checked,
0019 would have shipped with three live consumers of services it believed were unreachable.

## The fail-open trap in the inert stand-in, and why the shape is not settled

The compact way to make an inert stand-in satisfy ten different interfaces is a proxy whose
every property read returns a no-op function. That is a fail-open, and it must not be used: a
consumer writing `if (service.enabled)` reads a function, which is truthy, so an inert provider
would report itself as *more* capable than the real one rather than less. The same applies to
any capability flag these services expose.

An inert stand-in therefore has to fail closed on reads it does not understand — a property
read it cannot resolve must be falsy, not callable — while still supplying the event
properties consumers subscribe to, since those are usually instance fields rather than
prototype members and so cannot be recovered from the real class's prototype alone.

Settling that shape needs the real consumers' usage read, and then the patched build run; it is
a behaviour question about upstream code, not something to decide by reading alone. Until then
the design above is a plan and not a result.
