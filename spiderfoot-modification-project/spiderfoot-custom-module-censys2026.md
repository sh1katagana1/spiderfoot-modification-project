# Spiderfoot Custom Module - Censys

***

## Goal
The default Censys module in Spiderfoot still uses the old API model with the old API ID and Secret. It also only takes in IP Addresses and Netblocks. I want to modify it to work with the new API model, as well as take in a domain name and give me some SSL Cert details on it.

## Workflow
```
SpiderFoot finds a DOMAIN_NAME
        ↓
sfp_censys2026 receives it
        ↓
Queries Censys Web Property API
        ↓
Extracts SSL certificate information
        ↓
Creates new SpiderFoot events
```

## Script
```
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_censys
# Purpose:     Query Censys.io API
#
# Author:      Steve Micallef
#
# Created:     01/02/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     MIT
# -------------------------------------------------------------------------------


import json
import time
from datetime import datetime, timezone


from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_censys2026(SpiderFootPlugin):

    meta = {
        'name': "Censys",
        'summary': "Obtain SSL certificate information from Censys Web Property API.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://censys.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://search.censys.io/api",
                "https://search.censys.io/search/language",
                "https://github.com/censys/censys-postman/blob/main/Censys_Search.postman_collection.json",
            ],
            'apiKeyInstructions': [
                "Visit https://censys.io/",
                "Register a free account",
                "Navigate to https://censys.io/account",
                "Click on 'API'",
                
            ],
            'favIcon': "https://censys.io/assets/favicon.png",
            'logo': "https://censys.io/assets/logo.png",
            'description': "Discover exposures and other common entry points for attackers.\n"
            "Censys scans the entire internet constantly, including obscure ports. "
            "We use a combination of banner grabs and deep protocol handshakes "
            "to provide industry-leading visibility and an accurate depiction of what is live on the internet.",
        }
    }

    opts = {
        "censys_pat": "",
        "delay": 3,
        "expiration_warning_days": 30,
    }

    optdescs = {
        "censys_pat": "Censys Personal Access Token.",
        "delay": "Delay between requests.",
        "expiration_warning_days": "Days before expiry to generate SSL_CERTIFICATE_EXPIRING.",
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
            "DOMAIN_NAME",
            
        ]

    def producedEvents(self):
        return [
            "SSL_CERTIFICATE_RAW",
            "SSL_CERTIFICATE_ISSUED",
            "SSL_CERTIFICATE_ISSUER",
            "SSL_CERTIFICATE_MISMATCH",
            "SSL_CERTIFICATE_EXPIRED",
            "SSL_CERTIFICATE_EXPIRING",
            "INTERNET_NAME"
        ]

    def queryWebProperty(self, hostname):
        headers = {
            "Authorization": f"Bearer {self.opts['censys_pat']}",
            "Accept": "application/json"
        }

        res = self.sf.fetchUrl(
            f"https://api.platform.censys.io/v3/global/asset/webproperty/{hostname}:443",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot",
            headers=headers
        )

        # API rate limit: 0.4 actions/second (120.0 per 5 minute interval)
        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)



    def parseApiResponse(self, res: dict):
        if not res:
            self.error("No response from Censys.io.")
            return None

        if res['code'] == "400":
            self.error("Invalid request.")
            return None

        if res['code'] == "404":
            self.info('Censys.io returned no results')
            return None

        if res['code'] == "403":
            self.error("Invalid API key.")
            self.errorState = True
            return None

        if res['code'] == "429":
            self.error("Request rate limit exceeded.")
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error(f"Unexpected HTTP response code {res['code']} from Censys API.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.info('Censys.io returned no results')
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from Censys.io: {e}")
            return None

        error_type = data.get('error_type')
        if error_type:
            self.error(f"Censys returned an unexpected error: {error_type}")
            return None

        return data

    def handleEvent(self, event):
        if self.errorState:
            return

        eventName = event.eventType

        if event.module == self.__name__:
            self.debug("Ignoring self-generated event")
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if self.opts['censys_pat'] == "":
            self.error(f"You enabled sfp_censys2026 but did not set a Personal Access Token!")
            self.errorState = True
            return

        eventData = event.data

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True



        qrylist = [eventData]
        for addr in qrylist:

            if self.checkForStop():
                return

            data = self.queryWebProperty(addr)

            if not data:
                continue

            rec = data.get("result")

            if not rec:
                self.info(f"Censys.io returned no results for {addr}")
                continue

            resource = rec.get("resource", {})
            cert = resource.get("cert")

            if not cert:
                self.info(f"No certificate found for {addr}")
                continue

            self.debug(f"Found certificate data for {addr}")
            
            evt = SpiderFootEvent(
                "SSL_CERTIFICATE_RAW",
                json.dumps(cert),
                self.__name__,
                event
            )
            self.notifyListeners(evt)

            subject_dn = cert.get("parsed", {}).get("subject_dn")

            if subject_dn:
                evt = SpiderFootEvent(
                    "SSL_CERTIFICATE_ISSUED",
                    subject_dn,
                    self.__name__,
                    event
                )
                self.notifyListeners(evt)

            issuer_dn = cert.get("parsed", {}).get("issuer_dn")

            if issuer_dn:
                evt = SpiderFootEvent(
                    "SSL_CERTIFICATE_ISSUER",
                    issuer_dn,
                    self.__name__,
                    event
                )
                self.notifyListeners(evt)

            root_domain = eventData.lower()
            seen = set()

            for name in cert.get("names", []):

                clean_name = name.lower()

                if clean_name.startswith("*."):
                    clean_name = clean_name[2:]

                if clean_name == root_domain:
                    continue

                if clean_name in seen:
                    continue

                seen.add(clean_name)

                evt = SpiderFootEvent(
                    "INTERNET_NAME",
                    clean_name,
                    self.__name__,
                    event
                )

                self.notifyListeners(evt)

            not_after = cert.get(
                "parsed",
                {}
            ).get(
                "validity_period",
                {}
            ).get(
                "not_after"
            )

            if not_after:

                try:
                    expiry = datetime.strptime(
                        not_after,
                        "%Y-%m-%dT%H:%M:%SZ"
                    ).replace(tzinfo=timezone.utc)

                    days_remaining = (
                        expiry - datetime.now(timezone.utc)
                    ).days

                    self.debug(
                        f"{addr} certificate expires {not_after}, "
                        f"{days_remaining} days remaining"
                    )

                    if days_remaining < 0:

                        evt = SpiderFootEvent(
                            "SSL_CERTIFICATE_EXPIRED",
                            not_after,
                            self.__name__,
                            event
                        )

                        self.notifyListeners(evt)

                    elif days_remaining <= self.opts["expiration_warning_days"]:

                        evt = SpiderFootEvent(
                            "SSL_CERTIFICATE_EXPIRING",
                            not_after,
                            self.__name__,
                            event
                        )

                        self.notifyListeners(evt)

                except Exception as e:
                    self.error(f"Error processing certificate expiry: {e}")

            cns = cert.get(
                "parsed",
                {}
            ).get(
                "subject",
                {}
            ).get(
                "common_name",
                []
            )

            if cns:

                cn = cns[0].lower()

                sans = [
                    n.lower().replace("*.", "")
                    for n in cert.get("names", [])
                ]

                if cn != eventData.lower() and cn not in sans:

                    evt = SpiderFootEvent(
                        "SSL_CERTIFICATE_MISMATCH",
                        cn,
                        self.__name__,
                        event
                    )

                    self.notifyListeners(evt)
# End of sfp_censys2026 class
```
Let's break down the script:

## Imports
```
import json
import time
from datetime import datetime, timezone

from spiderfoot import SpiderFootEvent, SpiderFootPlugin
```
1. json - It is used for json.loads() and json.dumps(). It converts between JSON text and Python dictionaries. As an example:
```
'{"name":"bob"}'
```
Becomes 
```
{"name":"bob"}
```
2. time - We use it to avoid hammering the Censys API. Used for
```
time.sleep()
```
3. datetime - For our use case it is used to calculate "how many days until the certificate expires?"
4. SpiderFootEvent - Represents a SpiderFoot event. As an example, the following means "I discovered a new hostname"
```
SpiderFootEvent(
    "INTERNET_NAME",
    "api.example.com",
    ...
)
```
5. SpiderFootPlugin - Every SpiderFoot module inherits from:
```
SpiderFootPlugin
```
Think of it as the SpiderFoot module template

## Module Class
```
class sfp_censys2026(SpiderFootPlugin):
```
This creates the module. Think: Create a SpiderFoot plugin called sfp_censys2026. Your sfp python filename has to be the same name shown here. 

## Meta
```
meta = {
```
This controls what SpiderFoot displays in the UI. 

1. 'name': "Censys" - Shows up in: Settings/Modules
2. 'summary' - A short description of the module
3. 'useCases' - Tells SpiderFoot "What kind of investigations use this module?"
4. 'dataSource' - Where does the data come from?

## Opts
```
opts = {
    "censys_pat": "",
    "delay": 3,
    "expiration_warning_days": 30,
}
```
These are module settings. Think configuration variables
1. censys_pat - Your API key.
2. delay - How long to wait between API calls. For example, time.sleep(3)
3. expiration_warning_days - Controls "When do we emit SSL_CERTIFICATE_EXPIRING?" Typically I will set this to 30 days. This way if I run a scan of a hostname and it shows me the SSL_CERTIFICATE_EXPIRING event in the results I know it's certificate expires in < 30 days. 

This is essentially the section in the UI under Settings, where you click the Censys module and it will have an input field for you to put your API key in plus set configurations then save it. 

## optdescs
```
optdescs = {
```
This is the descriptions in the UI for the module.

## setup()
```
def setup(self, sfc, userOpts=dict()):
```
SpiderFoot runs this when loading the module. By doing self.sf = sfc here it will later allow:
```
self.sf.fetchUrl()
```
To factor in for deduplication so it can show unique values
```
self.results = self.tempStorage()
```
Sets up a temporary storage for these values.

## watchedEvents()
```
def watchedEvents(self):
```
This tells SpiderFoot :What events should wake me up?" Normally when you create a scan and check box a few modules, they will lay dormant if the input is not one they are waiting for. If one module produces an event of IP_ADDRESS, and a second module has IP_ADDRESS in their watchedEvents list, that means that module will fire up and enrich the IP address once it sees it be created by the other module.

For our use case we are waiting for a DOMAIN_NAME.
```
return [
    "DOMAIN_NAME"
]
```
Whenever someone either puts in a domain name to kick off a scan, or during a scan another module produces a DOMAIN_NAME event in it's results, this module will fire off. 

## producedEvents()
```
def producedEvents(self):
        return [
            "SSL_CERTIFICATE_RAW",
            "SSL_CERTIFICATE_ISSUED",
            "SSL_CERTIFICATE_ISSUER",
            "SSL_CERTIFICATE_MISMATCH",
            "SSL_CERTIFICATE_EXPIRED",
            "SSL_CERTIFICATE_EXPIRING",
            "INTERNET_NAME"
```
When I just query the Censys API using Curl, I get a lot of JSON fields back. I dont need every field, but Censys "produces" these regardless. Here is where I state what I want this Censys module to produce for Events, for other modules to fire off on. In some cases these may not even be used for other modules to pivot off of and may just be for OSINT enrichment values by themselves, lilke seeing if a certificate is expiring. All of these events are already ones that come in Spiderfoot inside of db.py, s we do not need to create new ones for this module. I may have a correlation rule, however, that fires off when a scan produces an SSL_CERTIFICATE_EXPIRING event. That correlation rule may generate a notice that this domain's certificate is expiring within 30 days. Again, maybe not an event that would kick off another module, but an event that will add enrichment alerts via correlation rules.

## queryWebProperty()
```
def queryWebProperty(self, hostname):
        headers = {
            "Authorization": f"Bearer {self.opts['censys_pat']}",
            "Accept": "application/json"
        }

        res = self.sf.fetchUrl(
            f"https://api.platform.censys.io/v3/global/asset/webproperty/{hostname}:443",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot",
            headers=headers
        )

        # API rate limit: 0.4 actions/second (120.0 per 5 minute interval)
        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)
```
Let's break that into its parts.
```
headers = {
    "Authorization": f"Bearer {self.opts['censys_pat']}",
    "Accept": "application/json"
}
```
Is equivalent to me doing:
```
curl -H "Authorization: Bearer TOKEN"
```
The censys_pat was created in our ops section earlier.
```
self.sf.fetchUrl(...)
```
Is equivalent to 
```
requests.get(...)
```
Then we have the URL section
```
https://api.platform.censys.io/v3/global/asset/webproperty/{hostname}:443
```
Then we add a sleep timer to not hammer the Censys API.
```
time.sleep(self.opts['delay'])
```

## parseApiResponse()
```
def parseApiResponse(self, res: dict):
```
This is your safety checkpoint. You can see we cover a number of HTTP Status Codes, like 404, 429, 200, etc. For example:
```
if res['code'] == "404":
``` 
Means that Censys has no record.
```
if res['code'] == "429":
```
This means the rate limit was exceeded.

```
data = json.loads(res['content'])
```
This converts the API response into a Python dictionary.

## handleEvent()
This is the heart of the module. SpiderFoot calls this every time a DOMAIN_NAME event arrives. Let's look at its parts:
```
if eventData in self.results:
```
If your domain name was example.com, this avoids querying example.com multiple times.

```
data = self.queryWebProperty(addr)
```
This is what calls the Censys API

```
resource = rec.get("resource", {})
cert = resource.get("cert")
```
This extracts the certificate. 

```
json.dumps(cert)
```
That stores the entire certificate in a raw state. It's to generate the SSL_CERTIFICATE_RAW event.

```
subject_dn
```
This extracts the distinguished name from the certificate, for example cn=example.com. It's to generate the SSL_CERTIFICATE_ISSUED event

```
issuer_dn
```
This extracts the certificate issuer value, for example Amazon RSA 2048 M04. It's used to generate the SSL_CERTIFICATE_ISSUER event. 

```
for name in cert.get("names", [])
```
This is to loop through the SAN names (Subject Alternative Name) in the certificate. This is great to get subdomains from the apex domain. This is called a FOR loop, where it will look at the JSON field that has the SAN values, like:
```
[
 "*.api.example.com",
 "*.billing.example.com",
 ...
]
```
and it will do a few things to that data:
1. Remove wildcard - When the domain names have an asterisk indicating a wildcard, it removes it. For example:
```
clean_name = clean_name[2:]
```
Converts
```
*.api.example.com
```
into
```
api.example.com
```

2. Deduplicate - We want unique values so if the same domain name is in the SAN list that has already been in the list, we don't need it twice. 
```
seen = set()
```
Prevents duplicates. 

3. Generate INTERNET_NAME - This will create the results in the INTERNET_NAME section of the Summary after the scan. For us it would be the multiple SAN names.
```
SpiderFootEvent(
    "INTERNET_NAME",
    clean_name,
    ...
)
```

## Expiration Logic
This will extract:
```
not_after
```
Example:
```
2026-10-07T23:59:59Z
```
Then it will convert the text into a date:
```
datetime.strptime(...)
```
Then it will calculate:
```
days_remaining
```
Example:
```
121
```
It then does some If/Else statements, like: If
```
days_remaining < 0
```
Then the module will emit:
```
SSL_CERTIFICATE_EXPIRED
```
If:
```
days_remaining <= 30
```
The module will emit:
```
SSL_CERTIFICATE_EXPIRING
```


## CN Mismatch Detection
This extract:
```
common_name
```
For example, example.com. It will compare against the Domain searched and the SAN list. If the certificate doesn't match the host, then the module will emit:
```
SSL_CERTIFICATE_MISMATCH
```

## Final Flow
```
SpiderFoot UI
      │
      ▼
DOMAIN_NAME
      │
      ▼
sfp_censys2026
      │
      ▼
Censys Web Property API
      │
      ▼
Certificate
      │
      ├── SSL_CERTIFICATE_RAW
      ├── SSL_CERTIFICATE_ISSUED
      ├── SSL_CERTIFICATE_ISSUER
      ├── SSL_CERTIFICATE_EXPIRED
      ├── SSL_CERTIFICATE_EXPIRING
      ├── SSL_CERTIFICATE_MISMATCH
      │
      ▼
SAN Names
      │
      ▼
INTERNET_NAME
      │
      ├── api.example.com
      ├── billing.example.com
      ├── identity.example.com
      ├── metrics.example.com
      ├── profile.example.com
      └── sso.example.com
```

## Summary
This is a good custom SpiderFoot module because it teaches nearly every major SpiderFoot development concept in a single file.
































