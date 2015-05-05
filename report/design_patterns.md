## Design Patterns
Both patterns below are would be appropriate to use on the SPACS system, though 
if one were used, it may not be necessary to implement both. Both the Facade 
and Adapter patterns would be relevant given the design constraint that SPACS be 
designed to allow easy implementation of alternative PTU programs. Both 
patterns were also chosen because they allow for increasingly complex systems 
without making the overall system and interactions within more complicated.

### Facade Pattern
The Facade pattern would be appropriate to use in the SPACS system, to provide 
a simplified interface for User and PTU objects to interface with SPACS. 
With a facade implemented over the core SPACS system, it would be easier for 
alternative PTU programs to be implemented as they could be built to interact 
with SPACS without any intuition of what is occurring underneath/behind the 
facade.

### Adapter Pattern
The Adapter pattern would be appropriate for use on the PTU class, simplifying 
the interaction of SPACS with alternative PTU programs. Various differences and 
requirements of different PTU's would be abstracted behind the PTU adapter, 
hiding the complexities from the core SPACS system. This allows for simplified 
communication between the objects and a simpler overall architecture.