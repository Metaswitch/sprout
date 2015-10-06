ISC Interface
=============

The *ISC interface* is the interface between Sprout (acting as the
S-CSCF) and an application server (AS, also referred to as a
TAS). This document gives an overview of the interface itself and how
it works, and then walks through the design and implementation of this
interface in Sprout.

For specification details, see the
[Application Server Guide](http://clearwater.readthedocs.org/en/stable/Application_Server_Guide/index.html).

Contents
--------

* [Overview](#overview)
    * [Basic call flow](#basic-call-flow)
    * [Application Servers](#application-servers)
    * [S-CSCF call processing](#s-cscf-call-processing)
    * [Application Server Interface](#application-server-interface)
    * [Initial Filter Criteria](#initial-filter-criteria)
* [The Sprout implementation](#the-sprout-implementation)
    * [AS chains](#as-chains)
    * [Internal MMTEL AS](#internal-mmtel-as)
    * [Detailed AS chain handling](#detailed-as-chain-handling)
    * [Third-party registration](#third-party-registration)
* [References](#references)

Overview
========

Basic call flow
---------------

A call or other communication begins with an *initial request*, i.e.,
a SIP request such as an INVITE or a MESSAGE that is not part of an
existing dialog (and not a CANCEL). The initial request is sent from
the *originating UE* (user element), via Bono, to Sprout. Sprout
applies various processing, possibly including invoking one or more
application servers, and then optionally sends the message, via Bono,
to one or more *terminating UEs*.

The response to the initial request follows the same path as the
initial request. Subsequent requests within the same dialog (ACK, BYE,
etc) follow the agreed route (established by `Record-Route:` headers),
which usually omits Sprout and most application servers.

Application Servers
-------------------

An *application server* (AS) is a SIP network entity which can observe
or modify calls as they go through Sprout. It receives an initial
request from Sprout, and chooses whether to

* Route (proxy) the request back to Sprout for subsequent processing,
  optionally with modifications to headers or body.

* Act as a
  [B2BUA](https://en.wikipedia.org/wiki/Back-to-back_user_agent)
  passing the request back to Sprout as directed by
  its internal business logic. It may fork the call, divert it to an
  alternate destination, etc.

* Give a final response itself, which may be to reject the call or to
  accept it itself. In this case the initial request goes no further,
  and in particular does not reach a terminating UE.

An application server may also initiate calls, but this is not handled
specially within Sprout. It must set the `;orig` parameter on the URI
in the `Route:` header pointing at Sprout if it requires originating
handling on its request (in addition to terminating handling which is
always applied).

S-CSCF call processing
----------------------

Within Sprout, an initial request receives

1. *Incoming handling* - standard SIP routing, recognising the ODI token, etc.

2. *Originating handling* - processing on behalf of the originating user.

3. *Terminating handling* - processing on behalf of the terminating user.

4. *Outgoing handling* - actual delivery of the message, i.e., looking
  up the registered bindings of the terminating user and calling them.

Application servers may be invoked during originating handling and
during terminating handling.

If a terminating application server diverts the call to a new target
user, processing goes back to step&nbsp;2 to apply a special flavour
of originating handling to the call, and proceeds with subsequent
steps.

At all times Sprout is working in a particular *session case* on
behalf of a *served user*. Initially the session case is *originating*
and the served user is the originating user. Then Sprout turns the
call around (at this point it could go to a different server, or a
remote call could arrive into the Sprout flow). Then the session case
is *terminating* and the served user is the terminating (target)
user. If the call is then diverted, the session case becomes
*originating-cdiv* which is a special flavour of originating, before
becoming terminating again.

Application Server Interface
----------------------------

Sprout interacts with application servers over *ISC*, the application
server interface. This is just SIP with some specified details,
including the following:

* The `Route:` of the initial request must be preserved by the AS when
  it sends any subsequent requests. This happens automatically for a
  routing AS, but a B2BUA AS must take special care to preserve the
  route. The topmost `Route:` header contains the *ODI token* within
  the URI, a special value which indicates to Sprout what stage it is
  at in the processing of this call. ODI stands for *original dialog
  identifier*. It allows the AS to change the details of the request,
  or fork it, without upsetting Sprout's processing of the call.

* The `P-Served-User:` is set by Sprout to inform the AS of the user
  it is to serve the registration state of that user, and the session
  case under which it is serving them.

Initial Filter Criteria
-----------------------

A *user*, identified by their public user identity (IMPU), has a set
of *initial filter criteria* (iFCs). These are stored in Homestead
(and in the HSS) as part of the user's Service Profile. (The name
refers to the fact that iFCs apply only to initial
requests. "Subsequent filter criteria" were abandoned early on in the
development of IMS.)

Each iFC consists of a condition and an action. The condition is a
collection of *service point triggers* (SPTs), combined using AND, OR,
and NOT. Each SPT is a condition on the SIP method, session case,
request URI, SIP headers, or SDP lines of the initial request. The
action of the iFC is the URI of an application server, along with some
additional information.


The Sprout implementation
=========================

AS chains
---------

When an initial request arrives, Sprout determines the session case
and the served user and looks up the iFCs for that user. It then
creates an *AS chain*. This contains the sequence of iFCs to be
applied to the call within this session case. The steps in the AS
chain are (naturally!) called *AS chain links*.

Sprout then evaluates the iFCs in order against the current request,
until it finds the first match. At this point it proxies the request
on to the specified AS URI. It inserts into a request a `Route:`
header containing an ODI token pointing to the next AS chain link.

If the AS passes the request back to Sprout, Sprout recognises the ODI
token, retrieves the corresponding chain, and evaluates the iFCs in
order against the now-current request (which may have been modified by
the AS), starting at the link specified by the token. If it finds
another match, it proxies the request on to this new AS as before.

If the end of the chain is reached with no further match, Sprout
proceeds to its next step - either turning the call around and
commencing terminating processing (creating a new chain), or
commencing outbound processing and actually calling the registered
terminating UE(s).

Notice that the iFCs are read when the chain is created, and not
re-read during the call. The specs are clear that if the iFCs are
modified during the call (e.g., by an AS), this does not affect the
in-progress chain.

The ODI token supplied to the AS is only valid until Sprout receives a
final response from the AS. 3GPP TS 23.218 s5.2.3 step 5 suggests
possible approaches for an AS that wants to send a final response and
then make a correlated onward call. In fact Sprout only expires the
token when the initial transaction that created the AS chain is
terminated, so there is a short grace period.

Internal MMTEL AS
-----------------

Sprout has a built-in AS which implements a subset of the MMTEL
function. It is invoked when the URI `sip:mmtel.<domain>` appears in
the iFCs.

The internal MMTEL AS is invoked synchronously by function call,
rather than asynchronously by SIP message passing. This complicates the
Sprout internals.

When acting as an originating application server, the MMTEL AS either
modifies the current request in place, or rejects the call directly.

When acting as a terminating application server, the MMTEL AS either
modifies the current request in place, rejects the call directly, or
diverts the call. Diverting the call tail-recursively invokes the
relevant part of Sprout's incoming request handling. This causes
originating-cdiv and terminating handling to be invoked in the usual
way. To facilitate this, it carries the AS chain link (the in-memory
equivalent of the ODI token) and passes it to the recursive
invocation.

Detailed AS chain handling
--------------------------

When Sprout's stateful proxy code evaluates a link in the AS chain, it
receives a *disposition* which tells it what to do next. The
evaluation does one of the following:

* If the link's iFC doesn't match, nothing happens. The link returns
  `Next`, to indicate that the link has completed synchronously and
  the stateful proxy should immediately proceed to the next link.

* If the internal application server is invoked and it inspects and/or
  modifies the current request, the link also returns `Next`.

* If there are no links left in the chain, nothing happens. The link
  returns `Complete` to indicate the the stateful proxy should proceed
  with the next step of call processing.

* If the internal application server (or the AS chain link processing
  itself) has given a final response to the caller directly, the link
  returns `Stop`. There is nothing further for the stateful proxy to
  do, and it simply cleans up and returns.

* If the iFC indicates that an external application server should be
  invoked, it alters the current request to add the appropriate
  headers and sets the requested target to the application server's
  URI. The link returns `Skip`, indicating that the stateful proxy
  should skip to outgoing processing to proxy the request out
  statefully.

There are separate methods within the stateful proxy code to handle
originating and terminating processing. Each repeatedly evaluates the
links in the AS chain as long as `Next` is returned, returning the
result (which is never `Next`).

The incoming request handler retrieves an existing chain (if one is
indicated by an ODI token), or else creates a new one. It then invokes
originating processing. If this returns `Complete`, it invokes
terminating processing. The latest disposition is now `Complete`,
`Stop`, or `Skip`. If it is `Stop`, it proceeds no further; otherwise,
it invokes outgoing processing.

Third-party registration
------------------------

Third-party registration is handled a little differently. Logically
this is because REGISTERs are terminated at Sprout.

Whenever a REGISTER is received (either a real one, or a synthetic one
generated within Sprout due to a registration expiry or
network-initiated deregister), Sprout processes the REGISTER
completely. It then retrieves the iFCs and evaluates each of them
(synchronously) against the received REGISTER. All application servers
from matching iFCs are then sent an appropriate REGISTER request,
simultaneously. That request is based on the received request as
usual, plus appropriate headers, but in its body it may contain the
request and the response, and other information as indicated by the
iFC.


References
==========

The ISC interface is part of the IMS specification defined by the
[3GPP](http://www.3gpp.org/). The
[specification](http://www.3gpp.org/specification-numbering) can be
tricky to navigate, so this section contains a summary of the key
places to look in the 3GPP docs. The terminology used here is defined
elsewhere in this document.

For precise chapter and verse supporting individual functions and
behaviour, please see comments throughout the code.

We have followed the latest available version of each document; at the
time of writing this was typically version 11 or 12. The links are to
the official specs, which are ZIPped Word documents, sometimes with
ancillary materials. We have also provided links to the parallel ETSI
specs, which contain the same content under a different number, as
PDF.

[3GPP TS 24.229](http://www.3gpp.org/ftp/Specs/archive/24_series/24.229/24229-b50.zip)
([ETSI PDF](http://www.etsi.org/deliver/etsi_ts/124200_124299/124229/11.05.00_60/ts_124229v110500p.pdf),
[3GPP all versions](http://www.3gpp.org/ftp/Specs/html-info/24229.htm))
is the key reference for what each component must do with SIP traffic.
Look here for precise details of how and when ASs are invoked, how
ODIs are recognised, which headers to set and strip, etc.

* For Sprout, *s5.4* is the most important section.

    * *s5.4.1* (especially *s5.4.1.7*) covers registration handling.

    * *s5.4.3.1* covers how to determine the session case.

    * *s5.4.3.2* covers originating handling.

    * *s5.4.3.3* covers terminating handling.

*s5.7* covers correct AS behaviour; Sprout's behaviour should be
complementary.

[3GPP TS 23.218](http://www.3gpp.org/ftp/Specs/archive/23_series/23.218/23218-c10.zip)
([ETSI PDF - older version only](http://www.etsi.org/deliver/etsi_ts/123200_123299/123218/11.05.00_60/ts_123218v110500p.pdf),
[3GPP all versions](http://www.3gpp.org/ftp/Specs/html-info/23218.htm))
gives an overview of application server invocation.

* *s5.2* and *s6.9.2* cover how iFCs are interpreted.

* *s6.3 - s6.5* cover how registration, originating, and terminating
  requests are handled by Sprout.

* *s9* discusses the various modes of operation of an AS.

[3GPP TS 29.228](http://www.3gpp.org/ftp/Specs/archive/29_series/29.228/29228-b70.zip)
([ETSI PDF](http://www.etsi.org/deliver/etsi_ts/129200_129299/129228/11.07.00_60/ts_129228v110700p.pdf),
[3GPP all versions](http://www.3gpp.org/ftp/Specs/html-info/29228.htm))
defines the format and meaning of iFCs.

* The XML schema *CxData_Type_Rel11.xsd* attached to the spec defines
  the exact format of the iFCs.

* *sB.2.2 - sB.2.3* give a UML model of the iFCs and explain what the
  fields mean.

* *sC* gives a simple example set of iFCs.

* *sF* gives the definition of each SPT and how to interpret it.

