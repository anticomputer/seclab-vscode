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

## What the real consumers actually touch, and the scope question it raises

The outside consumers were read rather than guessed at. They do not call methods; they read
**observable instance fields** and then call `.get()` or `.read(reader)` on them — the
remote-connections toggle reads `environmentName` and `state` that way, and calls
`setEnvironmentName` only in response to a user action.

That settles two things and opens a third.

It settles that a prototype-derived stand-in is not enough: observables are instance fields, so
a stand-in built from the real class's prototype would not have `state` at all, and the first
read would throw rather than fail closed.

It settles that the blanket no-op proxy is doubly wrong here: `state.get()` would return a
function, which is truthy, so a window with an inert provider would render as *sharing
enabled*. Falsy-on-unknown is not a stylistic preference; it is the difference between a null
provider and a provider that lies in the dangerous direction.

What it opens is a scope question against the plan. The plan asks for the Mission Control
services to be nulled alongside the cloud sandbox agent-host service. The agent-host service
has no consumer outside its own definition, so nulling it is free. The Mission Control sharing
service and the connection-customization service do have live consumers, so nulling them means
supplying a stand-in shaped to what those consumers read, or their UI breaks.

The proposal, rather than ten hand-written null classes or one unsafe proxy, is a single small
table in the patch naming, per service, which members are observables, which are events and
which are methods, with a shared builder that returns a falsy constant observable,
`Event.None`, and an async no-op respectively. One mechanism, one place to audit, and the
shape comes from the declared interface rather than from guesswork.

Pending the coordinator's decision on that scope, since it is a departure from the plan's
wording even though it serves the plan's purpose.

## The declared members, and why the table needs safe values rather than safe kinds

Reading the two interfaces that have live outside consumers turned the fail-open from a
predicted hazard into a demonstrated one, and changed the design.

`IMissionControlSharingService` declares `state: IObservable<'disabled' | 'connecting' |
'enabled'>`, `environmentName: IObservable<string | undefined>`, and the methods
`setEnvironmentName`, `setEnabled` and `setProjectFolders`. The neighbouring Mission Control
service declares `hosts: IObservable<readonly IMissionControlHost[]>`, `accountKey: string |
undefined`, **`enabled: boolean`**, and six methods.

`enabled: boolean` is the predicted trap, in the tree, declared: under a proxy that returns a
no-op function for every property read, `service.enabled` is a function and therefore truthy.
A tab window would report the Mission Control provider as enabled precisely because it had been
nulled.

`state` sharpens the rule further. Returning `undefined` for it is not safe either, because
consumers compare it against the three named values; `undefined` is neither `'disabled'` nor
`'enabled'`, so a `=== 'disabled'` guard fails and a `!== 'enabled'` guard passes, and which
one a given call site uses decides whether the result is contained or not. The stand-in has to
return the explicit contained value, `'disabled'`.

So the table records a **safe value per member**, not merely a kind:

| member | kind | stand-in value |
|---|---|---|
| `state` | observable | `constObservable('disabled')` — the named contained state, never `undefined` |
| `environmentName` | observable | `constObservable(undefined)` |
| `hosts` | observable | `constObservable([])` |
| `accountKey` | property | `undefined` |
| `enabled` | property | `false`, explicitly, because the default must be falsy |
| all methods | method | async no-op |

The general rule the builder enforces, and which the tests should pin: a member the table does
not name is not silently defaulted to anything callable. Guessing in the capable direction is
how a null provider becomes a provider that lies.

## Status at the 2026-11-16 wind-down

**Proven.** Patch 0019 exists, the full queue applies, and 265 unit tests pass, including nine
that pin the stand-in. Those nine were checked against the defect they exist to catch: a proxy
returning a no-op function for every property read fails five of them, so they are evidence
rather than decoration. The inventory above was read from the pinned tree, and the two upstream
invariants patch 0018 rests on were each shown to fail under defect injection.

**Not proven, and not claimed.** No runtime proof has been run for increments 3 or 4. Nothing
here shows the patched build behaving as described in a real window; "the queue applies" and
"the tests pass" are not that, and the project's own history on this branch is that review and
unit tests have repeatedly passed over checks that could not fail. The patch-reach check, which
is what would show 0019's module reachable from the shipped desktop build, needs a full upstream
tree and so runs in CI rather than locally; it has not run on this change yet.

**Exact next step.** Add the sole-consumer invariants for 0019, pinning the facts its argument
depends on: that the ten registrations and the three contributions are the only ones, and that
the remote contribution is what registers agents for another connection. Each must be shown to
fail under injection before it is recorded. Then the security review round on 0019, then close
R12-2 in the register with its regression test, then the runtime proof.

**The runtime proof has to show both halves**, per the coordinator's direction of 2026-11-16: a
request routed by a forged agent id or participant mention is refused, and the tab's own gated
agent still works. The second half is what stops the first from being satisfied by a build that
simply does nothing. Each nulled provider's `seclab.null-provider.registered` event is asserted
positively, not inferred from an absent connection.

**Builds.** None dispatched or fetched in this stretch; no run ids to carry forward. The U and
F variants from the increment-2 proof are not valid baselines for increment 3 or 4, since main
now contains 0017; a vulnerable baseline has to branch from before the patch under test or
revert it explicitly.

**Awaiting the owner.** Nothing. Finding R12-2 stays open and registered rather than deferred by
acceptance, because increment 4 closes it; the register reports exactly that one problem on this
branch, which is the accurate state until 0019 lands with increment 3.

## The real-build run, and why it has not happened yet

A macOS build of this branch was dispatched and succeeded: Actions run `44158800692`, head
`4f8caab0`. Every required check passed on that commit except the docs gate, which fails for
exactly one reason — the two high findings on this branch cite fix commits that are not on main,
and the register deliberately refuses to let one change both introduce and close a high.

`./seclab fetch macos-branch` then refused the build, by design: a build is only fetched when the
commit itself passed the gates, not merely when it compiled. That rule came from an earlier CI
review, and it is doing its job here, so it was not worked around. The artefact is sound and will
be fetchable once the docs gate is green on the exact SHA, which needs the "found and fixed
before landing" status the register is adding.

The app already present in the branch-build location is from an older run, `42239456909` at repo
`26137e98`, which predates these patches. It is not evidence about 0019 and was not used.

So the ordinary-window and tab-window runs are serialised behind the register change rather than
behind anything in the patches. What they have to show, when they run:

- an ordinary window, where the three workbench contributions construct the real classes and the
  window behaves as it does on main;
- a tab window, where the same three emit `seclab.null-provider.registered` as they are
  withheld.

The two are each other's control, which is the point: the tab side alone would be an absence, and
absence is not containment. Both constructions happen at `AfterRestored` without anything having
to drive them, so neither side depends on a step that could silently not run.

The question the runs exist to settle is the one the round 13 reviewer named and could not check
by reading: patch 0019 changes dependency construction from upstream's topological graph walk to
re-entrant resolution inside the wrapper's constructor. That is reasoned to be equivalent, and
reasoning is not a booted window.
