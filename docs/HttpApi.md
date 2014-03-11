Sprout nodes expose a HTTP interface on port 9888. This is done so that the Chronos timer component can notify Sprout when a registration has expired, and so that Homestead can notify Sprout when a Registration-Termination-Request is received from the HSS.

# Registration API

The API consists of one URL (`/registrations`), which accepts only `DELETE` requests. This URL has a mandatory query parameter, `send-notifications`, which must be either `true` or `false`.

The body sent to this URL must be a JSON document containing a `"registrations"` key, where the value is a list of objects, each of which have a mandatory `"primary-impu"` key and an optional `"impi"` key. Other keys are ignored

For example:

```
{ “registrations”: [ { “primary-impu”: “sip:...” }, { “primary-impu”: “sip:...”, “impi”: “…” }, … ] }
```

Responses have the following error codes:

* `400 Bad Request`, if the body is not a JSON document as above or the query parameters are invalid
* `500 Internal Server Error`, if an internal failure (e.g. dropped memcached connection) means that the request can't be handled
* `200 OK`, if the request is processed

Any other request to this URL (e.g. a `GET`) is rejected with `405 Method Not Allowed`.
