Project Clearwater is backed by Metaswitch Networks.  We have discontinued active support for this project as of 1st December 2019.  The mailing list archive is available in GitHub.  All of the documentation and source code remains available for the community in GitHub.  Metaswitch’s Clearwater Core product, built on Project Clearwater, remains an active and successful commercial offering.  Please contact clearwater@metaswitch.com for more information. Note – this email is for commercial contacts with Metaswitch.  We are no longer offering support for Project Clearwater via this contact.

# Sprout

This repository contains the core Clearwater SIP function, specifically

*   sprout, the Clearwater SIP router
*   bono, the Clearwater SIP edge proxy
*   restund, the STUN/TURN server used by Clearwater
*   sipp, a SIP stress tool used for testing Clearwater.

## Sprout and Bono

Sprout is Clearwater's SIP router.  It provides most of Clearwater's S-CSCF
function.  It generally acts as a stateful SIP proxy.  It provides registrar
function, storing registration information in a memcached store distributed
across all sprout instances.  It also provides application server function,
retrieving Initial Filter Criteria documents from Homestead and acting on
them.  As well as supporting external application servers, sprout has built-in
support for MMTEL services.

Bono is Clearwater's edge proxy.  It provides limited P-CSCF function and the
some of Clearwater's S-CSCF function.  It generally acts as a stateful SIP
proxy, receiving SIP messages from users, checking their authenticity and
forwarding them to other bono instances or one of the sprout instances.

Sprout and bono share a lot of function and are in fact the same binary, just
started with different command-line arguments.  They are written in C++, using
[PJSIP](http://www.pjsip.org/) as a SIP stack, [curl](http://curl.haxx.se/) as
an HTTP client, and a selection of other open-source components.

## Restund

Clearwater's fork of restund is very similar to the
[original](http://www.creytiv.com/restund.html).  The only difference is that
the Clearwater fork communicates with Homestead to retrieve SIP digest
credentials, which are used to authenticate TURN flows.

## SIPp

Clearwater uses [SIPp](http://sipp.sourceforge.net/) for stress testing.  The
Clearwater version features improved TCP scalability and also comes packaged
with scripts for simulating Clearwater call load and analyzing/reporting the
results.

## Further Information

*   To build and run sprout, see the [Development](docs/Development.md) page.
