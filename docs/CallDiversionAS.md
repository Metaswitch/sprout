# Call Diversion AS

The Call Diversion AS is based on the call diversion function in the [MMTEL TAS](http://clearwater.readthedocs.org/en/stable/Clearwater_Call_Diversion_Support/index.html).

However, the MMTEL TAS requires an XDMS (XML Database Management Server).  Since the call diversion configuration is fixed, this just adds unnecessary complexity.

*   It requires an additional XDMS to be installed to store the "simservs" XML.

*   It requires dual-provisioning.

Instead, Call Diversion AS allows call diversion configuration to be encoded into the AS's URI in the IFCs.

## Invocation

The MMTEL TAS function is invoked using a URI of the form `sip:mmtel@home-domain` or `sip:mmtel.home-domain` and is configured via a simservs XML document.

The Call Diversion AS is instead invoked using a URI of the form `sip:communication-diversion@home-domain` or `sip:communication-diversion.home-domain` and is configured via parameters encoded on this URI, as follows.

*   conditions - specifies a set of plus-separated conditions, any of which invokes diversion (if absent, divert unconditionally) - conditions can be
    *   busy
    *   not-registered
    *   no-answer
    *   not-reachable

*   target - specifies the SIP URI to divert to

*   no-reply-timer - specifies the delay before deciding the call has no answer (seconds)

So, for example, `sip:communication-diversion@home-domain;conditions=busy+no-answer;target=sip:123467890%40home-domain;no-reply-timer=30` would divert to `sip:1234567890@home-domain` if busy or after 30s of ringing. 

## Function

Apart from being invoked differently, the Call Diversion AS behaves very similarly to the existing MMTEL TAS call diversion function.

*   It acts as a stateful proxy for the initial INVITE transaction, but is not involved in subsequent in-dialog transactions.

*   If the call diversion criteria are met (e.g. the initial target is busy or does not reply), the Call Diversion AS cancels the previous INVITE and sends a new INVITE to the new target.

*   The new INVITE request includes both Diversion and History-Info headers describing who diverted the call and why.  (Both headers are included to improve compliance with peer devices.)

*   On diversion, a 181 Call Is Being Forwarded response is sent to the caller.

*   Invoking the Call Diversion AS also enables handling of 3xx SIP responses.

## Configuration

The only configuration options (apart from those encoded in the URI parameters) are the standard ones required by all Sprout-based components, i.e.

*   home_domain
*   sprout_hostname
*   local_ip
*   public_ip
*   public_hostname
*   sas_server.

These are configured in /etc/clearwater/config.

