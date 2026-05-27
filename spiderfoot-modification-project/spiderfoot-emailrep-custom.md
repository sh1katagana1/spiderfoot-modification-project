# Spiderfoot Custom Module - Emailrep

***

## Goal
To modify the current Spiderfoot Emailrep module to actually produce relevant results. I want to refactor it to focus on normalized intelligence enrichment instead of scanner output.

The new architecture supports:
1. structured events
2. reusable entities
3. graph pivots
4. future AI analysis
5. correlation
6. risk scoring
7. headless automation

## What does the original Emailrep module do?
The original sfp_emailrep.py module:
1. queried EmailRep.io
2. parsed JSON
3. only checked:
* credentials_leaked
* malicious_activity
4. only emitted:
* RAW_RIR_DATA
* EMAILADDR_COMPROMISED
* MALICIOUS_EMAILADDR

Problem:
1. almost all intelligence fields were ignored
2. data was mostly stored as raw blobs
3. poor correlation support
4. poor AI-readiness

## What fields does Emailrep actually return?
Here is some example output for an email address:
```
{
  "email": "acidicloop@gmail.com",
  "reputation": "high",
  "suspicious": false,
  "references": 10,
  "details": {
    "blacklisted": false,
    "malicious_activity": false,
    "malicious_activity_recent": false,
    "credentials_leaked": true,
    "credentials_leaked_recent": false,
    "data_breach": true,
    "first_seen": "01/01/2014",
    "last_seen": "04/11/2025",
    "domain_exists": true,
    "domain_reputation": "n/a",
    "new_domain": false,
    "days_since_domain_creation": 11225,
    "suspicious_tld": false,
    "spam": false,
    "free_provider": true,
    "disposable": false,
    "deliverable": true,
    "accept_all": false,
    "valid_mx": true,
    "primary_mx": "gmail-smtp-in.l.google.com",
    "spoofable": true,
    "spf_strict": false,
    "dmarc_enforced": false,
    "profiles": [
      "twitter"
    ]
  }
} 
```

## Script
Here is the full sfp_emailrep.py script
```
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_emailrep
# Purpose:      Searches EmailRep.io for email address reputation.
#
# Modified for structured intelligence enrichment output
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_emailrep(SpiderFootPlugin):

    meta = {
        'name': "EmailRep",
        'summary': "Search EmailRep.io for email address reputation.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://emailrep.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.emailrep.io/"
            ]
        }
    }

    opts = {
        'api_key': '',
    }

    optdescs = {
        'api_key': 'EmailRep API key.',
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):

        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['EMAILADDR']

    def producedEvents(self):

        return [
            'RAW_RIR_DATA',
            'EMAILADDR_COMPROMISED',
            'MALICIOUS_EMAILADDR',

            # Structured enrichment
            'EMAIL_REPUTATION',
            'EMAIL_PROVIDER',
            'EMAIL_SECURITY_POSTURE',
            'EMAIL_BREACH',
            'EMAIL_RISK_SCORE',
            'EMAIL_METADATA',

            # Pivotable entities
            'SOCIAL_MEDIA',
            'MAILSERVER',
            'DOMAIN_NAME'
        ]

    def query(self, qry):

        headers = {
            'Accept': "application/json"
        }

        if self.opts['api_key'] != '':
            headers['Key'] = self.opts['api_key']

        res = self.sf.fetchUrl(
            'https://emailrep.io/' + qry,
            headers=headers,
            useragent='SpiderFoot',
            timeout=self.opts['_fetchtimeout']
        )

        time.sleep(1)

        if res['content'] is None:
            return None

        if res['code'] == '400':
            self.sf.error('API error: Bad request')
            self.errorState = True
            return None

        if res['code'] == '401':
            self.sf.error('API error: Invalid API key')
            self.errorState = True
            return None

        if res['code'] == '429':
            self.sf.error('API error: Too Many Requests')
            self.errorState = True
            return None

        if res['code'] != '200':
            self.sf.error('Unexpected reply from EmailRep.io: ' + res['code'])
            self.errorState = True
            return None

        try:
            return json.loads(res['content'])

        except Exception as e:
            self.sf.debug(f"Error processing JSON response: {e}")

        return None

    def handleEvent(self, event):

        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == '':
            self.sf.error(
                "Warning: You enabled sfp_emailrep but did not set an API key!"
            )

        res = self.query(eventData)

        if res is None:
            return None

        details = res.get('details')

        if not details:
            return None

        # --------------------------------------------------
        # ALWAYS STORE RAW DATA
        # --------------------------------------------------

        evt = SpiderFootEvent(
            'RAW_RIR_DATA',
            json.dumps(res, indent=2),
            self.__name__,
            event
        )
        self.notifyListeners(evt)

        # --------------------------------------------------
        # EMAIL REPUTATION
        # --------------------------------------------------

        reputation = res.get('reputation')

        if reputation:

            evt = SpiderFootEvent(
                'EMAIL_REPUTATION',
                reputation,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        # --------------------------------------------------
        # COMPROMISED EMAIL
        # --------------------------------------------------

        credentials_leaked = details.get('credentials_leaked')

        if credentials_leaked:

            evt = SpiderFootEvent(
                'EMAILADDR_COMPROMISED',
                eventData + " [Credentials Leaked]",
                self.__name__,
                event
            )
            self.notifyListeners(evt)

            evt = SpiderFootEvent(
                'EMAIL_BREACH',
                'Credentials leaked in breach datasets',
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        # --------------------------------------------------
        # MALICIOUS ACTIVITY
        # --------------------------------------------------

        malicious_activity = details.get('malicious_activity')

        if malicious_activity:

            evt = SpiderFootEvent(
                'MALICIOUS_EMAILADDR',
                'EmailRep [' + eventData + ']',
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        # --------------------------------------------------
        # DOMAIN EXTRACTION
        # --------------------------------------------------

        if details.get('domain_exists'):

            try:

                domain = eventData.split('@')[1]

                evt = SpiderFootEvent(
                    'DOMAIN_NAME',
                    domain,
                    self.__name__,
                    event
                )
                self.notifyListeners(evt)

            except Exception as e:
                self.sf.debug(f"Error extracting domain: {e}")

        # --------------------------------------------------
        # MAILSERVER
        # --------------------------------------------------

        primary_mx = details.get('primary_mx')

        if primary_mx:

            evt = SpiderFootEvent(
                'MAILSERVER',
                primary_mx,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        # --------------------------------------------------
        # EMAIL PROVIDER TYPE
        # --------------------------------------------------

        provider_flags = []

        if details.get('free_provider'):
            provider_flags.append('Free Provider')

        if details.get('disposable'):
            provider_flags.append('Disposable Provider')

        for provider in provider_flags:

            evt = SpiderFootEvent(
                'EMAIL_PROVIDER',
                provider,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        # --------------------------------------------------
        # SOCIAL MEDIA PROFILES
        # --------------------------------------------------

        profiles = details.get('profiles', [])

        for profile in profiles:

            evt = SpiderFootEvent(
                'SOCIAL_MEDIA',
                profile,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        # --------------------------------------------------
        # SECURITY POSTURE
        # --------------------------------------------------

        security_posture = {
            'spoofable': details.get('spoofable'),
            'spf_strict': details.get('spf_strict'),
            'dmarc_enforced': details.get('dmarc_enforced'),
            'valid_mx': details.get('valid_mx'),
            'accept_all': details.get('accept_all')
        }

        evt = SpiderFootEvent(
            'EMAIL_SECURITY_POSTURE',
            json.dumps(security_posture),
            self.__name__,
            event
        )
        self.notifyListeners(evt)

        # --------------------------------------------------
        # EMAIL METADATA
        # --------------------------------------------------

        metadata = {
            'first_seen': details.get('first_seen'),
            'last_seen': details.get('last_seen'),
            'days_since_domain_creation': details.get('days_since_domain_creation')
        }

        evt = SpiderFootEvent(
            'EMAIL_METADATA',
            json.dumps(metadata),
            self.__name__,
            event
        )
        self.notifyListeners(evt)

        # --------------------------------------------------
        # RISK SCORE
        # --------------------------------------------------

        risk_score = 0

        if credentials_leaked:
            risk_score += 40

        if malicious_activity:
            risk_score += 50

        if details.get('spoofable'):
            risk_score += 20

        if details.get('disposable'):
            risk_score += 15

        if details.get('spam'):
            risk_score += 20

        evt = SpiderFootEvent(
            'EMAIL_RISK_SCORE',
            str(risk_score),
            self.__name__,
            event
        )
        self.notifyListeners(evt)
```

Let's go over the script:
### Imports
```
import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin
```
1. json - Used to:
* parse API responses
* store structured data
* emit JSON payloads

For example:
```
json.loads(res['content'])
```
converts raw API text into a Python dictionary
2. time - Used for:
```
time.sleep(1)
```
This avoids API rate limits
3. SpiderFootEvent - A very important Class. It creates events. For example:
```
SpiderFootEvent(
    'MAILSERVER',
    primary_mx,
    self.__name__,
    event
)
```
This means "I discovered a MAILSERVER entity."
4. SpiderFootPlugin - This is the base class for ALL SpiderFoot modules. Your module inherits from it class sfp_emailrep(SpiderFootPlugin). This gives your module:
* event handling
* logging
* HTTP requests
* threading
* listener notification
* SpiderFoot integration

### Module Metadata (meta)
```
meta = {
    'name': "EmailRep",
    ...
}
```
This defines:
1. UI information
2. module description
3. API references
4. categories
5. use cases

SpiderFoot uses this to:
1. display module info in UI
2. categorize modules
3. document APIs

Some important fields include:
1. name
```
'name': "EmailRep"
```
Human-readable module name.
2. flags
```
'flags': ["apikey"]
```
Tells SpiderFoot that this module requires/supports API keys
3. useCases
```
["Footprint", "Investigate", "Passive"]
```
Defines intended investigative usage
4. categories
```
["Search Engines"]
```
Used for module organization.

### Module Options (opts)
```
opts = {
    'api_key': '',
}
```
Defines module configuration settings. An example would be the EmailRep API key. SpiderFoot automatically injects:
* user-configured values
* UI settings

### setup()
```
def setup(self, sfc, userOpts=dict()):
```
This initializes the module. Think of it as the module startup logic. Some important lines include:
1. self.sf = sfc - This gives your module access to:
* SpiderFoot core functions
* HTTP requests
* logging
* DB
* utilities

2. self.results = self.tempStorage()
This creates some temporary deduplication storage It's used later to avoid duplicate lookups and duplicate events.

### watchedEvents()
```
def watchedEvents(self):
    return ['EMAILADDR']
```
This tells SpiderFoot "I want to receive EMAILADDR events." This means if ANY module emits EMAILADDR this module activates. This is called Event Chaining as SpiderFoot modules communicate ONLY through events.

### producedEvents()
```
def producedEvents(self):
```
This declares what event types this module can emit. SpiderFoot uses this for:
1. validation
2. storage
3. UI
4. correlation

This corresponds with later when we modify the db.py to add some custom events for mapping the results of emailrep to. We will add
1. EMAIL_REPUTATION
2. EMAIL_PROVIDER
3. EMAIL_SECURITY_POSTURE
4. EMAIL_RISK_SCORE
5. MAILSERVER

### query()
```
def query(self, qry):
```
This is the API communication layer. It does the following:
1. build request headers
2. send API request
3. handle errors
4. parse JSON

Some important parts are:
```
res = self.sf.fetchUrl(...)
```
SpiderFoot’s built-in HTTP client. Advantages:
1. proxy support
2. timeout handling
3. logging
4. consistency

```
if res['code'] == '429':
```
This is for error handling and handles rate limiting.

```
json.loads(res['content'])
```
This converts API response text into usable Python objects.

### handleEvent()
```
def handleEvent(self, event):
```
This is the heart of the module as MOST SpiderFoot module logic happens here. What happens here is the module:
1. receives an event
2. processes intelligence
3. emits new events

This is graph expansion in the Spiderfoot UI.

### Event Deduplication
```
if eventData in self.results:
    return None
```
Purpose:
1. prevent repeated lookups
2. avoid infinite loops
3. reduce API usage

### Query EmailRep
```
res = self.query(eventData)
```
This sends EMAILADDR (which in my example is acidicloop@gmail.com) to the EmailRep API.

### Extract details
```
details = res.get('details')
```
EmailRep nests most intelligence fields inside the json output field labeled "details" This function becomes:
1. details['spoofable']
2. details['profiles']
3. details['primary_mx']

### RAW_RIR_DATA
```
RAW_RIR_DATA
```
Purpose:
1. preserve original evidence
2. future reprocessing
3. AI re-analysis

This is forensic preservation

### EMAIL_REPUTATION
```
EMAIL_REPUTATION
```
Purpose:
1. enrichment classification
2. AI scoring
3. analyst context

An example output would be 'high'.

### EMAILADDR_COMPROMISED
```
EMAILADDR_COMPROMISED
```
This is triggered if:
```
credentials_leaked == True
```
Purpose:
1. breach intelligence
2. compromise tracking

### DOMAIN_NAME Extraction
```
domain = eventData.split('@')[1]
```
This converts:
```
acidicloop@gmail.com
```
into:
```
gmail.com
```
VERY important because DOMAIN_NAME is a major pivot entity.

### MAILSERVER Entity
```
MAILSERVER
```
Purpose:
1. infrastructure pivoting
2. correlation
3. shared MX analysis

Example: gmail-smtp-in.l.google.com

### EMAIL_PROVIDER
```
EMAIL_PROVIDER
```
Classifies:
1. free providers
2. disposable providers

Purpose:
1. phishing analysis
2. identity enrichment
3. AI scoring

### SOCIAL_MEDIA
```
SOCIAL_MEDIA
```
Purpose:
1. identity enrichment
2. future correlation pivots

Example output: twitter

### EMAIL_SECURITY_POSTURE
```
EMAIL_SECURITY_POSTURE
```
This grouped:
1. SPF
2. DMARC
3. spoofability
4. MX validation

Into ONE structured object. This was VERY smart architecturally. Why? Instead of:
```
EMAIL_SPF_FALSE
EMAIL_DMARC_FALSE
```
We group security posture, which avoids graph clutter.

### EMAIL_METADATA
```
EMAIL_METADATA
```
Stores:
1. first seen
2. last seen
3. domain age

Purpose:
1. temporal intelligence
2. timeline analysis
3. AI context

### EMAIL_RISK_SCORE
```
EMAIL_RISK_SCORE
```
Our custom scoring engine. This was a BIG architectural evolution. We moved from data collection toward intelligence analysis

Purpose:
1. prioritization
2. automation
3. AI triage
4. alerting


## DB.PY Modifications
This is where Spiderfoot has their events that results map to. If we have a result from a JSON output that doesnt map to a native event in this file, we have to add it as a custom entity. Because the Emailrep one does provide some additional intel that isnt mapped to a native entity, we do have to modify db.py in the spiderfoot directory. 
```
spiderfoot/db.py
```
In that file, you will see a long list of entities that look like:
```
['DOMAIN_REGISTRAR', 'Domain Registrar', 0, 'ENTITY'],
['DOMAIN_WHOIS', 'Domain Whois', 1, 'DATA'],
['EMAILADDR', 'Email Address', 0, 'ENTITY'],
['EMAILADDR_COMPROMISED', 'Hacked Email Address', 0, 'DESCRIPTOR'],
['EMAILADDR_DELIVERABLE', 'Deliverable Email Address', 0, 'DESCRIPTOR'],
['EMAILADDR_DISPOSABLE', 'Disposable Email Address', 0, 'DESCRIPTOR'],
['EMAILADDR_GENERIC', 'Email Address - Generic', 0, 'ENTITY'],
['EMAILADDR_UNDELIVERABLE', 'Undeliverable Email Address', 0, 'DESCRIPTOR'],
```
That is where you plug in your custom ones. Let's breakdown one of these fields:
```
['EMAILADDR', 'Email Address', 0, 'ENTITY'],
```
1. EMAILADDR - Internal event/entity identifier
2. Email Address - What UI/CLI displays
3. 0 - Not a root investigation entity
4. ENTITY - Event classification type

The most important field is the TYPE field. This defines how SpiderFoot treats the object. In the example above, ENTITY, means its a pivotable graph node. Other examples of pivotable graph nodes are:
1. EMAILADDR
2. DOMAIN_NAME
3. IP_ADDRESS
4. PERSON
5. MAILSERVER

Entities:
1. create graph relationships
2. enable correlations
3. can be reused across modules

Another TYPE is DESCRIPTOR. For example
```
['EMAIL_REPUTATION', 'Email Reputation', 0, 'DESCRIPTOR'],
```
DESCRIPTOR means its an attribute/classification about an entity. Examples:
1. reputation
2. risk score
3. disposable
4. compromised

Descriptors enrich entities but do NOT usually become pivots. 

Another TYPE is DATA
```
['EMAIL_SECURITY_POSTURE', 'Email Security Posture', 0, 'DATA'],
```
DATA means structured payload/blob/intelligence context. Usually:
1. JSON
2. metadata
3. raw records
4. supporting information

Here is what we need to add to db.py:
```
['EMAIL_REPUTATION', 'Email Reputation', 0, 'DESCRIPTOR'],
['EMAIL_PROVIDER', 'Email Provider Type', 0, 'DESCRIPTOR'],
['EMAIL_SECURITY_POSTURE', 'Email Security Posture', 0, 'DATA'],
['EMAIL_BREACH', 'Email Breach Information', 0, 'DESCRIPTOR'],
['EMAIL_RISK_SCORE', 'Email Risk Score', 0, 'DESCRIPTOR'],
['EMAIL_METADATA', 'Email Metadata', 0, 'DATA'],
['MAILSERVER', 'Mail Server', 0, 'ENTITY'],
```
You insert them after:
```
['EMAILADDR_UNDELIVERABLE', 'Undeliverable Email Address', 0, 'DESCRIPTOR'],
```
So that your list now looks like:
```
['EMAILADDR', 'Email Address', 0, 'ENTITY'],
['EMAILADDR_COMPROMISED', 'Hacked Email Address', 0, 'DESCRIPTOR'],
['EMAILADDR_DELIVERABLE', 'Deliverable Email Address', 0, 'DESCRIPTOR'],
['EMAILADDR_DISPOSABLE', 'Disposable Email Address', 0, 'DESCRIPTOR'],
['EMAILADDR_GENERIC', 'Email Address - Generic', 0, 'ENTITY'],
['EMAILADDR_UNDELIVERABLE', 'Undeliverable Email Address', 0, 'DESCRIPTOR'],

['EMAIL_REPUTATION', 'Email Reputation', 0, 'DESCRIPTOR'],
['EMAIL_PROVIDER', 'Email Provider Type', 0, 'DESCRIPTOR'],
['EMAIL_SECURITY_POSTURE', 'Email Security Posture', 0, 'DATA'],
['EMAIL_BREACH', 'Email Breach Information', 0, 'DESCRIPTOR'],
['EMAIL_RISK_SCORE', 'Email Risk Score', 0, 'DESCRIPTOR'],
['EMAIL_METADATA', 'Email Metadata', 0, 'DATA'],
['MAILSERVER', 'Mail Server', 0, 'ENTITY'],

['ERROR_MESSAGE', 'Error Message', 0, 'DATA'],
```

Let's breakdown each addition and why we want it for intelligence:
```
['EMAIL_REPUTATION', 'Email Reputation', 0, 'DESCRIPTOR'],
```
Purpose:
1. classify trust level
2. searchable enrichment
3. AI input

Example results would be:
1. high
2. medium
3. low

```
['EMAIL_PROVIDER', 'Email Provider Type', 0, 'DESCRIPTOR'],
```
Purpose:
1. classify provider type
2. phishing analysis
3. disposable/free provider detection

Example results would be:
1. Free Provider
2. Disposable Provider

```
['EMAIL_SECURITY_POSTURE', 'Email Security Posture', 0, 'DATA'],
```
Purpose:
1. store structured JSON
2. avoid ontology explosion
3. preserve grouped security posture

Example output would be:
```
{
  "spoofable": true,
  "spf_strict": false
}
```
This is because we combined multiple, note the TYPE is DATA.

```
['EMAIL_BREACH', 'Email Breach Information', 0, 'DESCRIPTOR'],
```
Purpose:
1. breach-specific enrichment
2. compromise classification
3. future AI analysis

```
['EMAIL_RISK_SCORE', 'Email Risk Score', 0, 'DESCRIPTOR'],
```
Purpose:
1. prioritization
2. alerting
3. AI triage
4. scoring pipelines

```
['EMAIL_METADATA', 'Email Metadata', 0, 'DATA'],
```
Purpose:
1. temporal intelligence
2. timestamps
3. domain age
4. future timeline analysis

```
['MAILSERVER', 'Mail Server', 0, 'ENTITY'],
```
Purpose:
1. infrastructure pivoting
2. shared MX analysis
3. graph relationships
4. future correlations

















































