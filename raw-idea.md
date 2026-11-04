I think the basic editor architecture itself should be reinvented beyond "trust this workspace?" to each tab following a browser style containment scope, driven by e.g. an docker sbx style workspace mount, scope can expand with the familiar trust/access questions, but at the process level it's locked down with actual sandbox/acl controls
code exec on an editor tab shouldn't imply full access to a system
I think that can be serviced without changing the front-end experience at all
and actually fits nicely with cloud vs local architecture considerations regardless
I think it's buildable with off the shelf things
then have tabs be cred sidecar routed for any token access requested by extensions and that kind of thing
