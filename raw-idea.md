kevinbackhouse  [11:25 AM]

Engineers are running all kinds of agents and extensions within VSCode and are probably loading all their PATs and other secrets in there for convenience. Would it instead be possible to sandbox the whole thing with the stuff that you're developing for Actions?

steiza  [11:56 AM]

Admittedly I am far from the VSCode architecture, but I think there's a lot to consider:

What arbitrary system-wide execution should plugins be allowed to execute on startup vs after prompting the user
When should things be chroot / jail / landlocked to the current directory vs have write access to your entire machine
What permissions should plugins have / what should happen if a plugin went from no startup scripts to a startup script, etc

anticomputer  [3:50 PM]

I think the basic editor architecture itself should be reinvented beyond "trust this workspace?" to each tab following a browser style containment scope, driven by e.g. an docker sbx style workspace mount, scope can expand with the familiar trust/access questions, but at the process level it's locked down with actual sandbox/acl controls
code exec on an editor tab shouldn't imply full access to a system
I think that can be serviced without changing the front-end experience at all
and actually fits nicely with cloud vs local architecture considerations regardless
@steiza we could pull a cursor and do seclab-vscode with the above
I think it's buildable with off the shelf things
then have tabs be cred sidecar routed for any token access requested by extensions and that kind of thing
