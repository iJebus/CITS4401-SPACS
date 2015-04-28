## If breaking system into modules/subsystems...

Subsystem decomposition. Describe how you would decompose SPACS into subsystems.
Describe the services provided by each subsystem. Justification of your subsystem
decomposition (such as coupling and cohesion) should be given. Are there other ways to
decompose the system?

### Authentication
This subsystem would provide authentication only, for the PTU login and web 
login. It is relatively loosely coupled, needing only login data provided and a 
call to the database to check the validity. It is highly cohesive as only 
authentication classes exists in module. 

### User Interface/Web UI
This subsystem would provide the web-based user interface for Pool Owners, Pool
Shop Admin and SPACS Admin to interact with SPACS. Loosely coupled, calling 
other subsystems for data when required but not effecting their running if in
an erroneous state. Highly cohesive as only UI information/forms/interfaces are 
in the subsystems.

### Message/Job Queue + Workers
This system places incoming tasks/actions into a queue, which is then accessed 
by 'workers' which process the tasks and remove them from the queue on successful 
completion. It's loosely coupled in that it only requires tasks to be input 
in the correct form. It's somewhat cohesive as while the tasks may vary 
(processing data vs sending emails), they are all still tasks. If necessary to 
improve cohesion, separate queues could be built for related types of tasks.

* Database
