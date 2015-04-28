## If breaking system into modules/subsystems...

Subsystem decomposition. Describe how you would decompose SPACS into subsystems.
Describe the services provided by each subsystem. Justification of your subsystem
decomposition (such as coupling and cohesion) should be given. Are there other ways to
decompose the system?

### Authentication
This subsystem would provide authentication only, for the PTU logins and the human logins to the UI.

* User Interface/Web UI
* Message Queue
* Data Processing
* Email/Communications
* Database
