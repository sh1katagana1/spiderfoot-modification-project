# Updating the SpiderFoot Censys Module for the Modern Censys API

This document summarizes everything we changed to modernize the SpiderFoot Censys module for the newer Censys Platform API v3.

It also explains:
- how SpiderFoot modules work
- how event/entity systems work
- how we normalized JSON into intelligence entities
- how we added custom entity types
- why correlations work the way they do

---

# 1. The Original Problem

The stock SpiderFoot Censys module was outdated.

It originally used:

```text
Old Censys Search API v2
API UID + Secret
Basic Authentication
```

But modern Censys now uses:

```text
Censys Platform API v3
Personal Access Tokens
Bearer Authentication
```

The original module therefore no longer worked correctly.

---

# 2. New Censys API Authentication

The old module used:

```python
Authorization: Basic base64(uid:secret)
```

The new Censys API uses:

```python
Authorization: Bearer <token>
```

We updated the module to support this new authentication model.

---

# 3. Updated Module Settings

We replaced the old settings:

```python
"censys_api_key_uid": "",
"censys_api_key_secret": "",
```

with:

```python
"censys_api_token": "",
```

inside:

```python
opts = {}
```

and:

```python
optdescs = {}
```

This automatically created a new API token field inside the SpiderFoot UI.

---

# 4. Updated API Endpoint

The old module queried:

```text
search.censys.io/api/v2/
```

We updated it to use:

```text
https://api.platform.censys.io/v3/global/asset/host/<ip>
```

using:

```python
headers = {
    'Authorization': f"Bearer {token}"
}
```

---

# 5. Understanding SpiderFoot Modules

A SpiderFoot module is basically:

```text
Receive entities
      ↓
Query external source
      ↓
Normalize data
      ↓
Emit new entities
```

SpiderFoot is fundamentally:

```text
an event-driven intelligence graph system
```

NOT:

```text
just an OSINT scanner
```

---

# 6. watchedEvents()

This function tells SpiderFoot:

```text
“What entity types should trigger this module?”
```

Example:

```python
def watchedEvents(self):
    return [
        "IP_ADDRESS",
        "IPV6_ADDRESS",
        "NETBLOCK_OWNER",
        "NETBLOCKV6_OWNER",
    ]
```

Meaning:

```text
When SpiderFoot discovers an IP or netblock,
run the Censys module.
```

---

# 7. producedEvents()

This function tells SpiderFoot:

```text
“What intelligence entities can this module create?”
```

Example:

```python
return [
    "BGP_AS_MEMBER",
    "NETBLOCK_MEMBER",
    "GEOINFO",
    "COMPANY_NAME",
    "STREET_ADDRESS"
]
```

These become:
- graph nodes
- searchable entities
- relationships
- future pivot points

---

# 8. Understanding Normalization

The Censys API returns raw JSON.

Example:

```json
{
  "location": {
    "country": "United States"
  }
}
```

SpiderFoot does NOT automatically understand arbitrary JSON.

We had to explicitly map fields into SpiderFoot entities.

Example:

| JSON | SpiderFoot Event |
|---|---|
| country | GEOINFO |
| asn | BGP_AS_MEMBER |
| bgp_prefix | NETBLOCK_MEMBER |
| organization.name | COMPANY_NAME |
| organization.street | STREET_ADDRESS |

This process is called:

```text
normalization
```

This is one of the hardest problems in:
- CTI
- SIEM
- SOAR
- ASM
- intelligence engineering

---

# 9. Understanding SpiderFootEvent

This creates intelligence entities.

Example:

```python
evt = SpiderFootEvent(
    "GEOINFO",
    geoinfo,
    self.__name__,
    pevent
)
```

Meaning:

```text
“I discovered geolocation information.”
```

---

# 10. notifyListeners()

This is the heart of SpiderFoot.

```python
self.notifyListeners(evt)
```

This:
- inserts entities into the graph
- stores intelligence
- triggers downstream modules
- creates relationships
- enables correlations

Without this:
SpiderFoot would only store raw JSON blobs.

---

# 11. The Initial JSON Parsing Problem

The new Censys API used a different JSON structure.

The old module expected:

```json
{
  "result": {
  }
}
```

But the new API returned:

```json
{
  "resource": {
  }
}
```

This broke parsing.

We fixed this using:

```python
rec = data.get("resource")

if not rec:
    rec = data.get("data", {}).get("resource")

if not rec:
    rec = data.get("result", {}).get("resource")

if not rec:
    rec = data.get("result")

if not rec:
    rec = data.get("data")
```

This allowed the module to handle multiple response structures.

---

# 12. Why Correlations Initially Appeared Empty

Browse and Correlations are different.

## Browse

Shows:

```text
stored entities
```

## Correlations

Shows:

```text
relationship density and overlap
```

Your early scans were too linear:

```text
IP
 ↓
ASN
 ↓
Location
```

Correlations become powerful once:
- multiple modules overlap
- entities recur
- infrastructure shares relationships

---

# 13. Adding Custom Entity Types

SpiderFoot stores its ontology inside:

```text
spiderfoot/db.py
```

Inside:

```python
eventDetails = [
```

Each entry looks like:

```python
[
    EVENT_NAME,
    HUMAN_LABEL,
    IS_DATA,
    CATEGORY
]
```

Example:

```python
['COMPANY_NAME', 'Company Name', 0, 'ENTITY']
```

---

# 14. Understanding ENTITY vs DESCRIPTOR vs DATA

## ENTITY

Graphable objects:

Examples:
- IP
- domain
- organization
- address
- hash

---

## DESCRIPTOR

Attributes/states:

Examples:
- suspicious
- compromised
- malicious
- high risk

---

## DATA

Large evidence blobs:

Examples:
- raw JSON
- HTML
- screenshots
- logs

---

# 15. Adding STREET_ADDRESS

We added:

```python
['STREET_ADDRESS', 'Street Address', 0, 'ENTITY']
```

inside:

```python
eventDetails
```

This allowed:

```text
street addresses
```

to become:

```text
first-class intelligence entities
```

instead of buried raw JSON.

---

# 16. Why This Matters

Once entities are normalized:

They become:
- searchable
- graphable
- correlatable
- exportable
- AI-friendly

This is foundational for:
- graph intelligence
- AI enrichment
- IOC correlation
- relationship analysis
- infrastructure clustering

---

# 17. Final Updated Censys Module

```python
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_censys
# Purpose:     Query Censys Platform API v3
# -------------------------------------------------------------------------------

import json
import time

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_censys(SpiderFootPlugin):

    meta = {
        'name': "Censys",
        'summary': "Obtain host information from the Censys Platform API v3.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Search Engines"],
    }

    opts = {
        "censys_api_token": "",
        "organization_id": "",
        'delay': 3,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxv6netblock': 120,
    }

    optdescs = {
        "censys_api_token": "Censys Personal Access Token.",
        "organization_id": "Optional organization ID.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):

        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):

        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
        ]

    def producedEvents(self):

        return [
            "BGP_AS_MEMBER",
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
            "GEOINFO",
            "RAW_RIR_DATA",
            "COMPANY_NAME",
            "STREET_ADDRESS"
        ]

    def queryHosts(self, qry):

        headers = {
            'Authorization': f"Bearer {self.opts['censys_api_token']}",
            'Accept': 'application/vnd.censys.api.v3.host.v1+json'
        }

        url = f"https://api.platform.censys.io/v3/global/asset/host/{qry}"

        if self.opts['organization_id']:
            url += f"?organization_id={self.opts['organization_id']}"

        res = self.sf.fetchUrl(
            url,
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot",
            headers=headers
        )

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    def parseApiResponse(self, res: dict):

        if not res:
            return None

        if res['code'] != '200':
            return None

        if res['content'] is None:
            return None

        try:
            return json.loads(res['content'])

        except Exception:
            return None

    def handleEvent(self, event):

        if self.errorState:
            return

        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        data = self.queryHosts(eventData)

        if not data:
            return

        rec = data.get("resource")

        if not rec:
            rec = data.get("data", {}).get("resource")

        if not rec:
            rec = data.get("result", {}).get("resource")

        if not rec:
            rec = data.get("result")

        if not rec:
            rec = data.get("data")

        if not rec:
            return

        evt = SpiderFootEvent(
            "RAW_RIR_DATA",
            json.dumps(rec, indent=2),
            self.__name__,
            event
        )

        self.notifyListeners(evt)

        location = rec.get('location')

        if location:

            geoinfo = ', '.join(
                [
                    _f for _f in [
                        location.get('city'),
                        location.get('province'),
                        location.get('country'),
                        location.get('continent'),
                    ] if _f
                ]
            )

            evt = SpiderFootEvent(
                "GEOINFO",
                geoinfo,
                self.__name__,
                event
            )

            self.notifyListeners(evt)

        autonomous_system = rec.get('autonomous_system')

        if autonomous_system:

            asn = autonomous_system.get('asn')

            if asn:

                evt = SpiderFootEvent(
                    "BGP_AS_MEMBER",
                    str(asn),
                    self.__name__,
                    event
                )

                self.notifyListeners(evt)

            bgp_prefix = autonomous_system.get('bgp_prefix')

            if bgp_prefix:

                evt = SpiderFootEvent(
                    "NETBLOCK_MEMBER",
                    str(bgp_prefix),
                    self.__name__,
                    event
                )

                self.notifyListeners(evt)

        organization = rec.get('whois', {}).get('organization', {})

        street = organization.get('street')

        if street:

            evt = SpiderFootEvent(
                "STREET_ADDRESS",
                street,
                self.__name__,
                event
            )

            self.notifyListeners(evt)

        org_name = organization.get('name')

        if org_name:

            evt = SpiderFootEvent(
                "COMPANY_NAME",
                org_name,
                self.__name__,
                event
            )

            self.notifyListeners(evt)
```

---

# 18. Final Architectural Insight

The biggest lesson from this project:

```text
The real value is NOT the API call.
The real value is the normalization layer.
```

Because normalization transforms:

```text
arbitrary external JSON
```

into:

```text
structured intelligence relationships
```

That is the foundation for:
- graph intelligence
- AI enrichment
- correlation engines
- infrastructure analysis
- CTI platforms
- advanced OSINT orchestration

