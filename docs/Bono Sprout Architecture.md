# Bono/Sprout Architecture

## Introduction

The Bono and Sprout components of Clearwater are implemented by a single C/C++ binary, with the different behaviours controlled by a set of command line options.

Much of the low-level SIP logic (transports, SIP message handling, transaction layer) is handled by [PJSIP](http://www.pjsip.org/ "PJSIP"), an open source C implementation of the SIP protocol stack.  Clearwater code handles higher layer functions like authentication, the registrar and the proxy.  Clearwater also adds support for a Websockets transport to PJSIP.

Apart from initialization and a few miscellaneous timer threads, all of Sprout's processing is performed in the context of callbacks from PJSIP.  PJSIP allows applications to register modules at different layers of the stack.  When a SIP message is received on a transport, the PJSIP framework calls the registered modules in priority order (lowest first) until one of them returns TRUE to indicate it has absorbed the message.  Similarly when an application sends a message, the PJSIP framework calls the registered modules in the reverse order allowing them to update/modify it until it is transmitted (in theory modules can also absorb messages in the transmit direction as well as the receive direction, but it doesn't tend to happen much if at all).

Functions like the transaction layer and the dialog layer are also implemented as modules, but will typically only operate on a message if instructed to by the application (see the section below on the stateless proxy for more details on this).

All module callbacks are synchronous, so if they need to interact with another process or system they must block.  Since Sprout interfaces with the registration store, Homestead and Homer it must be multi-threaded to avoid deadlocks.  Bono does not interact with other systems so can be single-threaded - although it does use separate threads for transport level and higher level processing, and can run with multiple threads on multi-core systems if required.

Bono/Sprout consists of five PJSIP modules and a number of supporting classes.  The PJSIP modules are

- the [stack module](#stack), which deals with low level functions like threading and logging
- the [options module](#options)
- the [authentication module](#auth)
- the [registrar](#registrar)
- the [stateful proxy](#proxy).

When running in Bono mode only the stack module, options module and stateful proxy module are enabled.  When running in Sprout mode all five modules are enabled.

## <a id="stack">Stack Module</a>

The stack module deals with low level functions like threading and logging.  It has the lowest priority and so is called first for received messages and last for transmitted ones.

The stack module manages two pools of threads.  One pool is donated to PJSIP and used to process transport level events and timers.  The other pool is a worker pool managed by the stack module itself, used to do all message processing above the transport layer.

The separate thread pools are required to allow parallel processing of messages received on the same TCP connection.  The PJSIP TCP transport layer serializes processing of received messages on each TCP connection, and does not issue another read to the TCP connection until the application signals it has finished with the message.  The stack module therefore clones each incoming message and queues it for processing by the separate worker thread pool.

The stack module is also responsible for low-level initialization and configuration of the PJSIP stack.

## <a id="options">Options module</a>

The options module implements support for receiving and responding to SIP OPTIONS methods.  The module registers for received requests with priority just lower than the authentication module, so OPTIONS messages are handled without authentication.

The function of the module is very simple.  If the request is an OPTIONS message with a request URI targeted at the Clearwater system, it sends a 200 OK response and returns true to PJSIP indicating it has absorbed the message.  Otherwise it returns false so PJSIP passes the message on to other modules.

## <a id="auth">Authentication Module</a>

The authentication module registers for received requests just below the transaction layer, so it can authenticate requests before they are processed either by the registrar or the stateful proxy,

When the authentication module receives a message it performs the following processing.

- It first calls a PJSIP function to verify the authentication information in the message.  If there is authentication information in the message, PJSIP calls out to the authentication module to retrieve authentication credentials.  The authentication module calls the HSSConnection class to retrieve the credentials from Homestead.  When the authentication module returns the credentials to PJSIP, PJSIP does the authentication checks.
- If PJSIP indicates the message was authenticated successfully, the module returns FALSE to PJSIP so the message continues up the stack.
- If PJSIP indicates the message had no credentials, and the message is not an ACK, the module sends a challenge response and returns TRUE to PJSIP to indicate it has absorbed the message.
- If PJSIP indicates the message had invalid credentials, and the message is not an ACK, the modules sends a Forbidden response and returns TRUE to PJSIP to indicate it has absorbed the message.

## <a id="registrar">Registrar Module</a>

The registrar module registers for received requests at the UA layer, so with a lower priority than the stateful proxy module.  It is essential that the registrar sees received requests before the stateful proxy - otherwise the proxy would proxy REGISTER requests that should be processed by the registrar.

On creation the registrar module is passed a Store object which exposes an interface used to store and retrieve registration data.  In live systems this Store is implemented by the MemcachedStore which uses a memcached cluster as the store, but there is a LocalStore option for testing.

When the registrar receives a REGISTER request it first checks whether it should process the request by checking the domain part of the request URI is a domain it is responsible for.  If not, it returns FALSE to PJSIP so it can be passed to the proxy.

If the registrar decides it should process the request it

- uses the store to retrieve existing bindings for the address of record
- updates these bindings using the information in the REGISTER
- writes the updated binding set back to the store
- builds and sends a response to the REGISTER (including the full set of bindings).

Individual bindings are either identified by the contact address, or, if supplied the +sip.instance parameter and reg-id parameters in the contact header (see [RFC5626](http://tools.ietf.org/html/rfc5626)).  +sip.instance/reg-id is the preferred mechanism as a restarting device that is assigned a different IP address will immediately replace its old bindings, avoiding unnecessary SIP forking.

Sprout is designed to run in a cluster with a shared memcached cluster as the registration store, so it is possible for multiple Sprout nodes to be handling concurrent REGISTERs for the same address of record, which could result in bindings being lost or corrupted.  The MemcachedStore class uses the CAS (check-and-set) function in memcached to implement an optimistic locking scheme.

- When the MemcachedStore reads the existing bindings from memcached, it remembers the CAS sequence number returned by memcached.
- When the registrar calls the MemcachedStore to write back the updated bindings, MemcachedStore increments the CAS sequence number and passes this updated value to memcached in the write command.  Memcached accepts the write if the sequence number it has stored is one less than the value specified on the write, and rejects it otherwise.
- If memcached rejects the write, MemcachedStore rejects the write command from the registrar, and the registrar repeats the read/update/write processing.
- The registrar only sends the response to the REGISTER when the write command returns successfully.

Expiry of bindings is the responsibility of the store.  In the MemcachedStore class, this is handled by removing any expired bindings before passing them to the registrar, and by using the longest expiry period in all the bindings as the expiry period for the memcached record.  This means that memcached automatically expires the record when all the bindings in it expire.

## <a id="proxy">Stateful Proxy Module</a>

The stateful proxy is the largest and most complex component within Sprout, partly because it has more complex interactions with PJSIP, and partly because it interfaces with all of the external stores.

The stateful proxy actually registers as two modules with PJSIP.

- The first module, termed the proxy module, registers for receiving requests and responses at the UA layer with a priority slight higher than the registrar.  This module handles all requests, setting up the necessary transactions, and any responses which do not correspond to an active transaction (for example, 200 OK retransmissions).
- The second module is a special kind of PJSIP module, termed a transaction user module.  It does not get invoked for received and sent messages, instead it gets invoked by the transaction layer for events on the transaction, including sent/received messages, timer expires and transport failures.

The function of the stateful proxy can be divided into [common processing](#commonproc), and [Bono](#bonoproc) and [Sprout](#sproutproc) specific processing.

### <a id="commonproc">Common Proxy Processing</a>

At a high-level a single proxied transaction comprises a single UAS transaction on which the initial request is received, and responses are sent, and one or more UAC transaction over which the request is forwarded and responses received.  The basic flow for a SIP transaction through the stateful proxy, ignoring differences between Bono and Sprout operation, is as follows.

PJSIP initially invokes the `on_rx_request` callback for the proxy module.  This

- does initial checking on the message
- creates the UAS transaction to handle the request and subsequent responses, and passes the request to this transaction.
- performs routing on the request, possibly doing a look-up in the registration store
- creates one or more UAC transactions and cloned requests to forward
- sets up data structures tracking the UAS and UAC transactions and the linkage between them
- loops sending the request on the UAC transactions.

Subsequent responses received on the UAC transactions are intercepted first by PJSIP's transaction layer which correlates them to an existing transaction and absorbs them so they are not passed to the `on_rsp_received` callback of the proxy module.  When the transaction layer has processed the response itself (doing whatever state transitions and other actions are required) it invokes the transaction user module with an event, including the received response message.  The transaction user module callback decides whether to forward the response immediately or whether to store it waiting responses on other UAC transactions (if the request was forked), following the rules in [RFC3261](http://tools.ietf.org/html/rfc3261).

Similarly, if the transaction layer in PJSIP processes some other event that changes the state of a UAC transaction or the UAS transaction (for example, a timeout, a transport failure or a state change caused by a transmitted response) it invokes the transaction user module callback with an event.  The callback processes the event which may in some cases cause it to send a response on the UAS transaction (for example, if the only UAC transaction times out, the transaction user module sends a timeout response on the UAS transaction).
Once final responses or timeouts have been received on all UAC transactions, and a final response sent on the UAS transaction, the proxy discards all record of the transaction.

There is an added subtlety for INVITE transactions because of the specific handling of the ACK message.  If the INVITE is rejected then the ACKs are sent/received independently on the UAS and UAC transactions and handled by the PJSIP transaction layer.  However, if the INVITE is successful (that is, gets a 200 OK response) the ACK cannot be handled by the transaction layer.  (This is as defined in the main SIP RFC, [RFC3261](http://tools.ietf.org/html/rfc3261).  The reason for this difference is because the ACK is allowed to bypass a proxy if the proxy does not add a record route header - if the ACK was considered part of the UAS and UAC transactions by the proxy it may never be in a position to consider the transactions completed.)  This (a) means the ACK will be received as a new request by the proxy module, so the proxy module has special case code for handling ACKs that doesn't create transactions.  It also raises the possibility that the 200 OK response may get retransmitted by the downstream endpoint on a UAC transaction after the proxy has forgotten about the transaction, so the proxy module has code to handle this in the `on_rsp_received` callback - essentially forwarding it as a stateless proxy would.

The other special case is handling of CANCEL requests.  These are handled initially by the `on_rx_request` function in the proxy module, which attempts to correlate the request to the UAS transaction it is cancelling.  If it finds the UAS transaction it marks the transaction as cancelled and attempts to send a CANCEL on all UAC transactions that are still active (that is, have not yet received a final response).  There is a potential race condition here as it is possible for the CANCEL to arrive while the original request is blocked waiting for targets from MemcachedStore, so (a) the initial processing of any request must create the UAS transaction before invoking MemcachedStore, and (b) on receiving targets from MemcachedStore the proxy must check that the UAS transaction hasn't been cancelled before proceeding.

### <a id="bonoproc">Bono / Edge Proxy Processing</a>

When the stateful proxy module is running as a Bono node, it performs various edge proxy specific functions, including

- tracking incoming client connections including authorization status
- bridging SIP transactions and dialogs between the untrusted and trusted zones (ports 5060 and 5058 respectively) and between transports where necessary
- policing SIP flows from the untrusted zone
- implements trust zone message manipulations, removing message headers when required
- load balancing requests across the Sprout nodes.

When running as a Bono node all routing of requests is performed based on route headers and request URI.  If a request cannot be routed based on route headers or the request URI then Bono will always route it to a Sprout node - it does not access the registration store directly itself.  This means that a Bono node will never fork a SIP request.

Each Bono node uses the ConnectionPool class to manage a pool of TCP connections to the Sprout nodes for this purpose.  The ConnectionPool class periodically recycles these connections to keep the load evenly spread across the Sprout nodes.

Bono tracks incoming client connections in the FlowTable class, including recording when the connection has been authenticated by the client correctly responding to a challenge from a Sprout node.  Each client connection is identified by a flow token which is used in Path and Route headers as per [RFC5626](http://tools.ietf.org/html/rfc5626) for ensuring that SIP flows for the client use the appropriate connection (both for security and NAT traversal purposes).

Bono polices requests from unauthenticated clients so that only requests destined for a Sprout node (which can challenge the request if necessary) are allowed.  This avoids some potential theft of service scenarios using SIP messages with pre-built Route headers designed to bypass the authentication.

SIP transactions and dialogs traversing a Bono node involve changes of port number, so Bono double Record-Routes itself on requests and checks for double Route headers as recommended by [RFC5658](http://tools.ietf.org/html/rfc5658).

### <a id="sproutproc">Sprout / Routing Proxy Processing</a>

When the stateful proxy module is running as a Sprout node it performs as a authoritative routing proxy instead of an edge proxy, using the registration data store to route requests to the destination clients.  If the target user has multiple active registrations then a Sprout proxy will fork the SIP request.

In addition, Sprout is responsible for managing service invocation, including invoking external application servers over the [ISC](#isc) interface and invoking the local [MMTEL services](#mmtel).

#### <a id="isc">ISC Interface</a>

The ISC interface is mainly handled by the AsChain class.  This class is invoked by the stateful proxy module at various points in processing to determine the set of application servers the request should be chained through, and which is the next application server in the chain.

If the AsChain class reports that an application server should be invoked next, the stateful proxy adds a route header with an ODI token and proxies the request as normal.  If the AsChain class reports there are no applications servers to invoke or that the end of the chain has been reached, the stateful proxy continues with normal dialog routing.

If the dialog is completely on-net then the Sprout node will handle both originating and terminating application server chains, one after the other.

#### <a id="mmtel">MMTEL Services</a>

The MMTEL services are invoked by the stateful proxy at the appropriate point in the proxy processing - for originating services when the UAS transaction has been set up, and for terminating services before the targets are calculated.

At a high-level the services involve three steps.

- Reading the appropriate iFC from Homestead using the HSSConnection class, and using these to decide whether to invoke services at all.
- Reading the appropriate MMTEL simservs document from Homer and using this to decide which services to invoke and the settings of those services.
- Implementing the services themselves which may involve various manipulations of the messages or even forking.

The services are implemented by the CallServices and SimServs classes.

## Memory Management

The memory management in Bono/Sprout needs some care because it uses two schemes - standard C/C++ new/delete memory management, and PJSIPs memory management system.  In general the latter is used for data tied to PJSIP interactions (mostly SIP messages and transactions), and the former is used for everything else.

The PJSIP memory management model is a [region-based memory management](http://en.wikipedia.org/wiki/Region-based_memory_management "region-based memory management") system.  Memory is allocated from a pool, but the entire pool must be freed at the same time - it is not possible to free individual allocations.  Deciding which pool to use for each allocation request needs care to avoid odd corruption problems or memory leaks.  For example, if you allocate memory from a pool that is never destroyed you will have a leak, and if you allocate memory from a pool that gets destroyed before you expect it, you can find the memory reused and corrupted under your feet.

The benefit of this scheme is that, if you allocate memory from the appropriate pool in most contexts then you do not have to worry about ensuring it gets freed - this will happen automatically when the pool is destroyed.

In general it is easy to work out which pool to allocate memory from - for example

- there are pools associated with each received message and each message being prepared for transmission, so if you are manipulating headers associated with that message it is generally safe to allocate from the message pool
- there are pools associated with individual transactions, so the stateful proxy is careful to allocate its own data structures keeping state associated with each transaction from those pools, and to make sure it NULLs out pointer references between them as transactions are destroyed
- there is a global pool used for a few things at initialization, but this should never be used for anything else.
