Sprout nodes can expose a management HTTP interface on port 9886 to allow various subscriber management operations. In order to configure this, set the `sprout_hostname_mgmt` config option to `<sprout_management_address>:9886` and run `sudo service clearwater-infrastructure restart`.

## IMPU

    /impu/<public ID>/bindings
    /impu/<public ID>/subscriptions

Make a GET request to this URL to retrieve information on the stored registration bindings or the stored subscriptions for the specified subscriber.

Responses:

  * 200 if successful, with a JSON body detailing the subscriber's bindings or subscriptions.
  
  ```
  {
    "bindings": {
      "<urn:uuid:49e11c5d-f0ba-4771-a76b-67de2d454503>": {
        "uri": "sip:81304765@1.2.3.4:54673;transport=tcp",
        "cid": "0gQAAC8WAAACBAAALxYAAOSfGPJkyUBlvwfKtjyDjB+PnKQRMSS9x\/Pt4csqoTgC@10.1.2.3",
        "cseq": 2,
        "expires": 1483653278,
        "priority": 0,
        "params": {
          "+sip.instance": "\"<urn:uuid:49e11c5d-f0ba-4771-a76b-67de2d454503>\""
        },
        "paths": [
          "sip:10.1.2.3:5061;transport=udp;lr"
        ],
        "timer_id": "Deprecated",
        "private_id": "alice@example.com",
        "emergency_reg": false
      },
      "sip:alice@1.2.3.4:54771;transport=tcp": {
        "uri": "sip:alice@1.2.3.4:54771;transport=tcp",
        "cid": "0gQAAC8WAAACBAAALxYAACm0Rca\/IhrC+8cgImfn\/4x\/xI73Fb102URc+RuBRk9xGm03o8ddHuY4GP3AJSR\/CQ--@10.1.2.3",
        "cseq": 15656,
        "expires": 1483656742,
        "priority": 0,
        "params": {
          "+g.3gpp.cs-voice": "",
          "+g.3gpp.icsi-ref": "\"urn%3Aurn-7%3A3gpp-application.ims.iari.gsma-vs\"",
          "+g.3gpp.smsip": "",
          "+g.oma.sip-im": "",
          "+g.oma.sip-im.large-message": "",
          "audio": "",
          "language": "\"en,fr\""
        },
        "paths": [
          "sip:10.1.2.3:5061;transport=udp;lr"
        ],
        "timer_id": "Deprecated",
        "private_id": "alice@example.com",
        "emergency_reg": false
      }
    }
  }
  ```
  
  ```
  {
    "subscriptions": {
      "10326075217247469568": {
        "req_uri": "sip:alice@1.2.3.4:54771;transport=tcp",
        "from_uri": "<sip:alice@example.com>",
        "from_tag": "10.1.2.3+5+20dd7858+bafb95da",
        "to_uri": "<sip:alice@example.com>",
        "to_tag": "10326075217247469568",
        "cid": "0gQAAC8WAAACBAAALxYAADTy1iSFJy2HbsFcJTA81IXn+fLBxfTtQ6Lv5DHiBo57SSrQSKHJ6VSUnmuubfkhwA--@10.1.2.3",
        "routes": [
          "sip:10.1.2.3:5061;transport=udp;lr"
        ],
        "expires": 1483653646,
        "timer_id": "Deprecated"
      }
    }
  }
  ```

  * 404 if Sprout has no information on this subscriber.
  * 500 if Sprout has been unable to contact its Memcached store.

---

    /impu/<public ID>

Make a DELETE request to this URL to perform an administrative de-registration of the the specified subscriber. Sprout tells Homestead that the subscriber has been de-registered, and this also triggers an SAR to the HSS if one has been configured. The specified public ID must be the subscriber's primary public identity.

Responses:

  * 200 if successful.
  * 400 if the subscriber is not assigned to this S-CSCF.
  * 500 if Sprout has been unable to contact its Memcached store.
  * 502 if Sprout has been unable to contact Homestead, or Homestead has reported a failure.
