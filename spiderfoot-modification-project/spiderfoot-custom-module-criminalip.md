# Spiderfoot Custom Module - Criminal IP

***

## Goal
Spiderfoot natively does not have a module for the Criminal IP API. This API gives good information about an IP Address and I would like to make a module for it. It does require an API Key, which you can get a free one.

## Curl Command
```
curl --location --request GET "https://api.criminalip.io/v1/asset/ip/report?ip=207.246.110.27&full=true" --header "x-api-key: <api key>"
```

## Inputs
IP Address

## Outputs
After running the Curl command, the specific JSON fields I am interested in are these:
```
{
  "ip": "207.246.110.27",
  "issues": {
    "is_vpn": false,
    "is_cloud": false,
    "is_tor": true,
    "is_proxy": false,
    "is_hosting": false,
    "is_mobile": false,
    "is_darkweb": false,
    "is_scanner": true,
    "is_snort": true
  },
  "score": {
    "inbound": "Critical",
    "outbound": "Moderate"
  },
```
Not all of these need to be inputs to kick off another module, but rather can be used for specific Correlation rules. Looking in db.py, the ones that are already included that we can use are:
```
['TOR_EXIT_NODE', 'TOR Exit Node', 0, 'DESCRIPTOR'],
['VPN_HOST', 'VPN Host', 0, 'DESCRIPTOR'],
['PROXY_HOST', 'Proxy Host', 0, 'DESCRIPTOR'],
```
The ones I will add as new entries are:
```
['SCANNER_HOST', 'Scanner Host', 0, 'DESCRIPTOR'],
['DARKWEB_HOST', 'Darkweb Host', 0, 'DESCRIPTOR'],
['SNORT_HOST', 'Snort Host', 0, 'DESCRIPTOR'],

['IP_INBOUND_RISK', 'IP Inbound Risk', 0, 'DESCRIPTOR'],
['IP_OUTBOUND_RISK', 'IP Outbound Risk', 0, 'DESCRIPTOR'],

['IP_IS_CLOUD', 'Cloud Infrastructure IP', 0, 'DESCRIPTOR'],
['IP_IS_HOSTING', 'Hosting Provider IP', 0, 'DESCRIPTOR'],
['IP_IS_MOBILE', 'Mobile Network IP', 0, 'DESCRIPTOR'],
```

## Script
Here is the sfp_criminalip.py script:
```
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_criminalip
# Purpose:      Query Criminal IP for IP reputation and threat intelligence.
#
# Author:       Custom Module
#
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_criminalip(SpiderFootPlugin):

    meta = {
        "name": "Criminal IP",
        "summary": "Query Criminal IP for IP reputation and threat intelligence.",
        "flags": ["apikey"],
        "useCases": ["Footprint", "Investigate", "Passive"],
        "categories": ["Reputation Systems"]
    }

    opts = {
        "api_key": ""
    }

    optdescs = {
        "api_key": "Criminal IP API key."
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = {}

        for opt in userOpts:
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["IP_ADDRESS"]

    def producedEvents(self):
        return [
            "RAW_RIR_DATA",

            "TOR_EXIT_NODE",
            "VPN_HOST",
            "PROXY_HOST",

            "SCANNER_HOST",
            "DARKWEB_HOST",
            "SNORT_HOST",

            "IP_IS_CLOUD",
            "IP_IS_HOSTING",
            "IP_IS_MOBILE",

            "IP_INBOUND_RISK",
            "IP_OUTBOUND_RISK"
        ]

    def queryCriminalIP(self, ipaddr):

        headers = {
            "x-api-key": self.opts["api_key"]
        }

        url = (
            "https://api.criminalip.io/v1/asset/ip/report"
            f"?ip={ipaddr}&full=true"
        )

        res = self.sf.fetchUrl(
            url,
            timeout=30,
            useragent="SpiderFoot",
            headers=headers
        )

        if not res:
            return None

        if res.get("code") != "200":
            self.info(
                f"Criminal IP returned HTTP {res.get('code')} "
                f"for {ipaddr}"
            )
            return None

        try:
            return json.loads(res.get("content"))
        except Exception as e:
            self.error(
                f"Unable to parse Criminal IP response for "
                f"{ipaddr}: {e}"
            )
            return None

    def handleEvent(self, event):

        eventName = event.eventType
        ipaddr = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if ipaddr in self.results:
            self.debug(f"Skipping already processed IP: {ipaddr}")
            return

        self.results[ipaddr] = True

        if not self.opts["api_key"]:
            self.error("No Criminal IP API key specified.")
            return

        data = self.queryCriminalIP(ipaddr)

        if not data:
            return

        # Store full response
        evt = SpiderFootEvent(
            "RAW_RIR_DATA",
            json.dumps(data, indent=2),
            self.__name__,
            event
        )

        self.notifyListeners(evt)

        issues = data.get("issues", {})

        #
        # TOR
        #
        if issues.get("is_tor") is True:
            evt = SpiderFootEvent(
                "TOR_EXIT_NODE",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # VPN
        #
        if issues.get("is_vpn") is True:
            evt = SpiderFootEvent(
                "VPN_HOST",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # Proxy
        #
        if issues.get("is_proxy") is True:
            evt = SpiderFootEvent(
                "PROXY_HOST",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # Scanner
        #
        if issues.get("is_scanner") is True:
            evt = SpiderFootEvent(
                "SCANNER_HOST",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # Darkweb
        #
        if issues.get("is_darkweb") is True:
            evt = SpiderFootEvent(
                "DARKWEB_HOST",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # Snort
        #
        if issues.get("is_snort") is True:
            evt = SpiderFootEvent(
                "SNORT_HOST",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # Cloud
        #
        if issues.get("is_cloud") is True:
            evt = SpiderFootEvent(
                "IP_IS_CLOUD",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # Hosting
        #
        if issues.get("is_hosting") is True:
            evt = SpiderFootEvent(
                "IP_IS_HOSTING",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # Mobile
        #
        if issues.get("is_mobile") is True:
            evt = SpiderFootEvent(
                "IP_IS_MOBILE",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # Risk scores
        #
        score = data.get("score", {})

        inbound = score.get("inbound")
        outbound = score.get("outbound")

        if inbound:
            evt = SpiderFootEvent(
                "IP_INBOUND_RISK",
                str(inbound),
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        if outbound:
            evt = SpiderFootEvent(
                "IP_OUTBOUND_RISK",
                str(outbound),
                self.__name__,
                event
            )
            self.notifyListeners(evt)
            
```

Let's breakdown the script:
```
meta = {
        "name": "Criminal IP",
        "summary": "Query Criminal IP for IP reputation and threat intelligence.",
        "flags": ["apikey"],
        "useCases": ["Footprint", "Investigate", "Passive"],
        "categories": ["Reputation Systems"]
    }
```
That is for the metadata for the module. In the UI, this information is useful, for example under scan types you can do scans based on the Use Case of Footprint. The useCases section above covers that. 

***

```
opts = {
        "api_key": ""
    }

    optdescs = {
        "api_key": "Criminal IP API key."
    }
```
This is saying to add an input field for the API Key in the UI under Settings/Criminal IP.

***

```
def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = {}

        for opt in userOpts:
            self.opts[opt] = userOpts[opt]
```
Think of it as the module's initialization function. SpiderFoot calls it when the scan starts so the module can get ready to run. 
1. def means you're defining a function.
2. The function is named setup.
3. SpiderFoot automatically calls this function when it loads your module.

What is self? You'll see self everywhere in Python classes. Think of self as: "This specific copy of the module." For example, if SpiderFoot loads your Criminal IP module, self refers to that loaded instance. When you write:
```
self.results
```
you're creating a variable that belongs to this module.

What is sfc? The sfc parameter is the SpiderFoot controller object. SpiderFoot passes it into your module automatically. Later this line stores it:
```
self.sf = sfc
```
Now anywhere in your module you can use:
```
self.sf.fetchUrl(...)
```
or
```
self.sf.hashstring(...)
```
or
```
self.sf.debug(...)
```
because you've saved the SpiderFoot framework object into self.sf. Think of it like:
```
self.sf = SpiderFootFramework
```
so later you can access SpiderFoot's built-in helper functions.

What is userOpts=dict()? When you run a scan, SpiderFoot loads the module options. For example:
```
opts = {
    "api_key": ""
}
```
In the UI you enter:
```
abc123xyz
```
for your Criminal IP API key. SpiderFoot passes those values into userOpts. So userOpts might look like:
```
{
    "api_key": "abc123xyz"
}
```
We also see:
```
self.results = {}
``` 
This means create an empty dictionary. In Python {} represents a dictionary which would have key:value pairs. As an example:
```
{
    "8.8.8.8": True,
    "1.1.1.1": True
}
```
Why do we need it? Imagine multiple modules discover the same IP. SpiderFoot might generate:
```
IP_ADDRESS = 8.8.8.8
```
more than once. Without tracking results:
```
8.8.8.8
8.8.8.8
8.8.8.8
```
you'd query Criminal IP three times. That wastes API credits. So later you'll see:
```
if ipaddr in self.results:
    return
```
meaning: Have we already looked up this IP? If yes:
```
return
```
which means: Stop processing. If no:
```
self.results[ipaddr] = True
```
which records it. So the self.results starts with nothing {} but ends with:
```
{
    "8.8.8.8": True
}
```

Let's look at the For loop next:
```
for opt in userOpts:
```
Suppose Spiderfoot passed:
```
userOpts = {
    "api_key": "abc123"
}
```
This loop goes through each option. First iteration:
```
opt = "api_key"
```
Inside the loop we see:
```
self.opts[opt] = userOpts[opt]
```
Let's substitute the values:
```
self.opts["api_key"] = userOpts["api_key"]
```
Which becomes:
```
self.opts["api_key"] = "abc123"
```
Before:
```
self.opts = {
    "api_key": ""
}
```
After:
```
self.opts = {
    "api_key": "abc123"
}
```
Now later in the module you can do:
```
self.opts["api_key"]
```
and get:
```
abc123
```
This entire function is basically doing three things:
```
def setup(self, sfc, userOpts=dict()):
```
1. Save SpiderFoot's framework object
```
self.sf = sfc
```
so you can use SpiderFoot functions later.

2. Create a cache
```
self.results = {}
```
so you don't query the same IP repeatedly.

3. Load the user's settings
```
for opt in userOpts:
    self.opts[opt] = userOpts[opt]
```
so if the user entered:
```
api_key = ABC123
```
your module can later access:
```
self.opts["api_key"]
```
when it makes API calls. That's why you'll see almost this exact setup() function in dozens of SpiderFoot modules. It's essentially the standard boilerplate that prepares a module to run.

***

Now we move onto the Watched Events and Produced Events
```
def watchedEvents(self):
        return ["IP_ADDRESS"]

    def producedEvents(self):
        return [
            "RAW_RIR_DATA",

            "TOR_EXIT_NODE",
            "VPN_HOST",
            "PROXY_HOST",

            "SCANNER_HOST",
            "DARKWEB_HOST",
            "SNORT_HOST",

            "IP_IS_CLOUD",
            "IP_IS_HOSTING",
            "IP_IS_MOBILE",

            "IP_INBOUND_RISK",
            "IP_OUTBOUND_RISK"
        ]
```

The watchedEvents is saying that the module is watching for an IP address to appear before it can fire off. This can either be by the user directly using an IP address as input for the scan, or another modules results output an IP Address.

That brings us to producedEvents. When a module is run, it will likely have some kind of output, a domain name, an ip address, a risk score, etc. These would be Events that other modules that you have activated in the scan can watch for and then they can fire off when they see that event being produced from another module. These can also be used by Correlation rules. You could have a rule that says if TOR_EXIT_NODE is produced as an event, then fire off a message saying "Tor node found".

***

Now let's look at the Criminal IP API call:
```
def queryCriminalIP(self, ipaddr):

        headers = {
            "x-api-key": self.opts["api_key"]
        }

        url = (
            "https://api.criminalip.io/v1/asset/ip/report"
            f"?ip={ipaddr}&full=true"
        )

        res = self.sf.fetchUrl(
            url,
            timeout=30,
            useragent="SpiderFoot",
            headers=headers
        )

        if not res:
            return None

        if res.get("code") != "200":
            self.info(
                f"Criminal IP returned HTTP {res.get('code')} "
                f"for {ipaddr}"
            )
            return None

        try:
            return json.loads(res.get("content"))
        except Exception as e:
            self.error(
                f"Unable to parse Criminal IP response for "
                f"{ipaddr}: {e}"
            )
            return None
```
This function has one job: "Given an IP address, ask Criminal IP about it and return the JSON response." Think of it as a helper function that handles all the API communication so the rest of your module doesn't need to worry about HTTP requests.

Let's walk through it line by line.
```
def queryCriminalIP(self, ipaddr):
```
You're creating a function called: queryCriminalIP() It accepts:
```
ipaddr
```
which might contain:
```
"8.8.8.8"
```
or
```
"1.1.1.1"
```
Example:
```
data = self.queryCriminalIP("8.8.8.8")
```

Next we build the headers:
```
headers = {
    "x-api-key": self.opts["api_key"]
}
```
Criminal IP API calls require you add a header called x-api-key along with the value. This will store that. Remember earlier:
```
self.opts["api_key"]
```
contains the API key entered by the user.

Next we build the URL:
```
url = (
    "https://api.criminalip.io/v1/asset/ip/report"
    f"?ip={ipaddr}&full=true"
)
```
Criminal IP has a specific API endpoint for querying about an IP address, it is the one above. In the normal call, ?ip= would have the actual IP value. The {ipaddr} is a substitution placeholder for whatever IP the module is currently enriching. That is what the f" is for, it's to insert the IP address value where the {} is. The full result after this building would be:
```
https://api.criminalip.io/v1/asset/ip/report?ip=8.8.8.8&full=true
```

Next we move to sending the actual request:
```
res = self.sf.fetchUrl(
    url,
    timeout=30,
    useragent="SpiderFoot",
    headers=headers
)
```
In Python, the requests library usually would do URL requests. SpiderFoot provides a helper function:
```
self.sf.fetchUrl()
```
Instead of doing:
```
requests.get(...)
```
many SpiderFoot modules use:
```
self.sf.fetchUrl(...)
```
because SpiderFoot automatically handles for you things like:
1. proxies
2. SSL verification
3. timeouts
4. user agents
5. logging

The request would look like:
```
GET https://api.criminalip.io/v1/asset/ip/report?ip=8.8.8.8&full=true

x-api-key: abc123
User-Agent: SpiderFoot
```

Timeout:
```
timeout=30
```
This means wait up to 30 seconds. If Criminal IP never responds 30 seconds later:
```
fetchUrl()
```
gives up. Without a timeout, the scan might hang forever.

User-Agent:
```
User-Agent: SpiderFoot
```
Many websites log this information. It tells the site who is making this request on behalf of the user. 

Then we have an if/else:
```
if not res:
    return None
```
Suppose the internet is down, DNS fails or Criminal IP is unreachable. Then:
```
res
```
might be:
```
None
```
or
```
False
```
This check says:
```
if not res:
```
meaning "Did we get nothing back?" If yes:
```
return None
```
which means: "Stop and tell the caller we failed."

Next we check the HTTP Status Code:
```
if res.get("code") != "200":
```
In HTTP, a status code of 200 means the webpage was received successfully. Most APIs return HTTP status codes. Some examples are:
```
Code	Meaning
200	Success
401	Unauthorized
403	Forbidden
404	Not Found
429	Rate Limited
500	Server Error
```
Suppose Criminal IP returns:
```
{
    "code": "401",
    "content": "Unauthorized"
}
```
Then:
```
res.get("code")
```
returns: "401" and this condition becomes:
```
if "401" != "200"
```
which is True, because != means does not equal. Whenever you do an if/else block, the code inside of the block is dependent on if the if statement is true or not. If it is true...run xyz code, if its not true, run what's in the Else block, or a different version is Try/Catch. 

Next we want to log the error:
```
self.info(
    f"Criminal IP returned HTTP {res.get('code')} "
    f"for {ipaddr}"
)
```
Note the f" again because we see more insertion points {}. So in this instance, If:
```
code = 401
ipaddr = 8.8.8.8
```
the message becomes:
```
Criminal IP returned HTTP 401 for 8.8.8.8
```
This appears in SpiderFoot's logs. 

So those things above are related to if the status code does not equal something, but what if we did get
```
HTTP 200
```
Now we need to convert the response into Python objects. Suppose in the Criminal IP response it returns:
```
{
  "ip": "8.8.8.8",
  "issues": {
    "is_tor": false
  }
}
```
At this point:
```
res.get("content")
```
contains:
```
'{"ip":"8.8.8.8","issues":{"is_tor":false}}'
```
Notice it's still just text.

```
json.loads(...)
```
transforms JSON text into a Python dictionary. So before it we had:
```
'{"ip":"8.8.8.8"}'
```
After it we now have:
```
{
    "ip": "8.8.8.8"
}
```
Now you can do:
```
data["ip"]
```
and get:
```
8.8.8.8
```

What is the Try Block? 
```
try:
```
means attempt this code.
```
return json.loads(res.get("content"))
```
Normally this succeeds. But suppose Criminal IP returns:
```
<html>Error</html>
```
instead of JSON. Then:
```
json.loads(...)
```
crashes and Python raises an exception. This is why we have the Except block:
```
except Exception as e:
```
means if anything breaks, run this code in this block. What is the code in this block?
```
self.error(
    f"Unable to parse Criminal IP response for "
    f"{ipaddr}: {e}"
)
```
This says to log the error. The output may look like:
```
Unable to parse Criminal IP response for 8.8.8.8:
Expecting value: line 1 column 1
```
The 'e' value is a placeholder for the actual error that returns. So we are given human readable explanatory text, and appending the actual error message at the end. Then:
```
return None
```
which tells the rest of the module: "Something went wrong."

In summary, if there is a successful call, we get:
```
{
    "ip": "8.8.8.8",
    "issues": {
        "is_tor": False,
        "is_vpn": True
    },
    "score": {
        "inbound": "Critical"
    }
}
```
If the call failed we get:
```
None
```
Later in the script there will be a call to this function, it will look like:
```
data = self.queryCriminalIP(ipaddr)
```
the variable data will either contain:
```
{
    "issues": {...},
    "score": {...}
}
```
or:
```
None
```

***

Now we move on to our final Function:
```
def handleEvent(self, event):

        eventName = event.eventType
        ipaddr = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if ipaddr in self.results:
            self.debug(f"Skipping already processed IP: {ipaddr}")
            return

        self.results[ipaddr] = True

        if not self.opts["api_key"]:
            self.error("No Criminal IP API key specified.")
            return

        data = self.queryCriminalIP(ipaddr)

        if not data:
            return

        # Store full response
        evt = SpiderFootEvent(
            "RAW_RIR_DATA",
            json.dumps(data, indent=2),
            self.__name__,
            event
        )

        self.notifyListeners(evt)

        issues = data.get("issues", {})

        #
        # TOR
        #
        if issues.get("is_tor") is True:
            evt = SpiderFootEvent(
                "TOR_EXIT_NODE",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # VPN
        #
        if issues.get("is_vpn") is True:
            evt = SpiderFootEvent(
                "VPN_HOST",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # Proxy
        #
        if issues.get("is_proxy") is True:
            evt = SpiderFootEvent(
                "PROXY_HOST",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # Scanner
        #
        if issues.get("is_scanner") is True:
            evt = SpiderFootEvent(
                "SCANNER_HOST",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # Darkweb
        #
        if issues.get("is_darkweb") is True:
            evt = SpiderFootEvent(
                "DARKWEB_HOST",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # Snort
        #
        if issues.get("is_snort") is True:
            evt = SpiderFootEvent(
                "SNORT_HOST",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # Cloud
        #
        if issues.get("is_cloud") is True:
            evt = SpiderFootEvent(
                "IP_IS_CLOUD",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # Hosting
        #
        if issues.get("is_hosting") is True:
            evt = SpiderFootEvent(
                "IP_IS_HOSTING",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # Mobile
        #
        if issues.get("is_mobile") is True:
            evt = SpiderFootEvent(
                "IP_IS_MOBILE",
                ipaddr,
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        #
        # Risk scores
        #
        score = data.get("score", {})

        inbound = score.get("inbound")
        outbound = score.get("outbound")

        if inbound:
            evt = SpiderFootEvent(
                "IP_INBOUND_RISK",
                str(inbound),
                self.__name__,
                event
            )
            self.notifyListeners(evt)

        if outbound:
            evt = SpiderFootEvent(
                "IP_OUTBOUND_RISK",
                str(outbound),
                self.__name__,
                event
            )
            self.notifyListeners(evt)
```

This is the heart of the module. Everything else is just setup and API communication. This function is where SpiderFoot says: "Hey Criminal IP module, I found something. Do you want to process it?" and your module decides what to do.

Imagine another module finds:
```
IP_ADDRESS = 8.8.8.8
```
SpiderFoot sends that event to every module watching for IP addresses. Our module has:
```
def watchedEvents(self):
    return ["IP_ADDRESS"]
```
so SpiderFoot calls:
```
self.handleEvent(event)
```
with the IP event. So, let's break this function down.

```
def handleEvent(self, event):
```
SpiderFoot automatically passes in an event object. Think of it like a package containing information. For example:
```
event.eventType
```
might be:
```
"IP_ADDRESS"
```
and
```
event.data
```
might be:
```
"8.8.8.8"
```
First it will extract information and put them in variables:
```
eventName = event.eventType
ipaddr = event.data
```
So, this would become:
```
eventName = "IP_ADDRESS"
ipaddr = "8.8.8.8"
```

Next is some debug logging:
```
self.debug(f"Received event, {eventName}, from {event.module}")
```
This writes a message into SpiderFoot's debug log. For example:
```
Received event, IP_ADDRESS, from sfp_dnsresolve
```
This helps you troubleshoot modules.

Next we have a duplicate check:
```
if ipaddr in self.results:
```
If you recall, self.results is your cache. Maybe it contains:
```
{
    "8.8.8.8": True
}
```
Now another module discovers:
```
"8.8.8.8"
```
again. This check becomes:
```
if "8.8.8.8" in self.results
```
which is: True. Then:
```
self.debug(
    f"Skipping already processed IP: {ipaddr}"
)
```
logs:
```
Skipping already processed IP: 8.8.8.8
```
and:
```
return
```
immediately exits the function. No API call, no wasted credits. If the IP is new:
```
self.results[ipaddr] = True
```
Suppose:
```
ipaddr = "8.8.8.8"
```
Now:
```
self.results
```
becomes:
```
{
    "8.8.8.8": True
}
```

Next we do a check if the API Key is present and valid:
```
if not self.opts["api_key"]:
```
This would mean the user never put in the API key under Settings. If the user forgot to configure:
```
api_key
```
Then:
```
self.opts["api_key"]
```
might be:
```
""
```
Which would be an empty string. This becomes:
```
if not "":
```
which is True. Because its true, it runs the code in the block:
```
self.error(
    "No Criminal IP API key specified."
)
```
Which logs this and stops:
```
return
```

Now we will query the Criminal IP API which we had setup earlier in the previous function. 
```
data = self.queryCriminalIP(ipaddr)
```
So build the URL query just as we set it up, and take ipaddr as an argument. Suppose:
```
ipaddr = "8.8.8.8"
```
This calls:
```
queryCriminalIP("8.8.8.8")
```
which contacts Criminal IP. Let's say Criminal IP returns:
```
{
    "issues": {
        "is_tor": True,
        "is_vpn": False
    },
    "score": {
        "inbound": "Critical"
    }
}
``` 
That gets stored in the variable:
```
data
```
So the data variable represents all of that JSON results above. 

Next we do a check lookup:
```
if not data:
    return
```
If:
```
queryCriminalIP()
```
failed, then:
```
data = None
```
and the module stops.

Next we store the raw response. Earlier we put in some producedEvents that we want for other modules to pivot off of. These are good to separate the values in to different boxes. But for later analysis, we also want just the full JSON response, not broken up, just all the raw data. 
```
evt = SpiderFootEvent(
    "RAW_RIR_DATA",
    json.dumps(data, indent=2),
    self.__name__,
    event
)
```
This creates a new SpiderFoot event. Think the original Event triggers the Criminal IP Module, then a new Event is created. Example:
```
RAW_RIR_DATA
```
Will contain:
```
{
  "issues": {
    "is_tor": true
  }
}
```
So after the scan runs, you will get the TOR event, but you will also get a field that is just the whole raw JSON response. The json.dumps() section converts Python data back into readable text.

next we want to notify the other modules that this event was created:
```
self.notifyListeners(evt)
```
All other activated modules in your scan may be just sitting dormant waiting on a specific event to pop up. To make sure all modules know a new event was created, this notifyListener is used. 

In the JSON results from the beginning, there was an 'issues' section:
```
issues = data.get("issues", {})
```
Suppose:
```
data
```
contains:
```
{
    "issues": {
        "is_tor": True,
        "is_vpn": False
    }
}
```
Then:
```
issues
```
becomes:
```
{
    "is_tor": True,
    "is_vpn": False
}
```

We know one of the values is checking if the IP is a Tor node, so:
```
if issues.get("is_tor") is True:
```
If that value is true, we would now get:
```
evt = SpiderFootEvent(
    "TOR_EXIT_NODE",
    ipaddr,
    self.__name__,
    event
)
``` 
This now makes the new event of TOR_EXIT_NODE, which we need to announce to all other modules using the notifyListener.
```
self.notifyListeners(evt)
```
Now every module watching: TOR_EXIT_NODE can react.

Same process applies to all the rest of them:
```
if issues.get("is_vpn") is True:
```
creates the event:
```
VPN_HOST
```
So repeat all of that for the Boolean values.

Then we get into the Risk Scoring part:
```
score = data.get("score", {})
```
Suppose Criminal IP returned:
```
{
    "score": {
        "inbound": "Critical",
        "outbound": "Moderate"
    }
}
```
Then:
```
score
```
becomes:
```
{
    "inbound": "Critical",
    "outbound": "Moderate"
}
```

Then we extract information:
```
inbound = score.get("inbound")
outbound = score.get("outbound")
```
Now:
```
inbound
```
contains:
```
"Critical"
```
and
```
outbound
```
contains:
```
"Moderate"
```

We create the Risk Event:
```
if inbound:
```
If a value exists:
```
evt = SpiderFootEvent(
    "IP_INBOUND_RISK",
    str(inbound),
    self.__name__,
    event
)
```
creates:
```
IP_INBOUND_RISK
Data: Critical
```
Then:
```
notifyListeners()
```
sends it to SpiderFoot. 

For the Outbound one, same thing applies. 
```
IP_OUTBOUND_RISK
Data: Moderate
```
gets created.

## Workflow Diagram
```
SpiderFoot finds IP
          ↓
handleEvent()
          ↓
Check duplicates
          ↓
Query Criminal IP
          ↓
Receive JSON
          ↓
Create RAW_RIR_DATA event
          ↓
Look at issues
          ↓
Create TOR/VPN/Proxy/etc events
          ↓
Look at risk scores
          ↓
Create risk events
          ↓
notifyListeners()
          ↓
SpiderFoot receives new events
          ↓
Other modules and correlations can use them
```




































  




















Domain```
curl --location --request GET "https://api.criminalip.io/v1/domain/reports?query=trinet.com&offset=0" --header "x-api-key: <YOUR_API_KEY>"
```
IP
```
curl --location --request GET "https://api.criminalip.io/v1/asset/ip/report?ip=207.246.110.27&full=true" --header "x-api-key: gmTpcvzs6hmx8jvFGNSeqI9BXPdeoKQbosM4mvrOug3lDrsjN9f0mEaz9RVe"


curl --location --request GET "https://api.criminalip.io/v1/asset/ip/report?ip=207.246.110.27&full=true" --header "x-api-key: gmTpcvzs6hmx8jvFGNSeqI9BXPdeoKQbosM4mvrOug3lDrsjN9f0mEaz9RVe" | jq  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   624  100   624    0     0    206      0  0:00:03  0:00:03 --:--:--   206
{
  "ip": "207.246.110.27",
  "issues": {
    "is_vpn": false,
    "is_cloud": false,
    "is_tor": true,
    "is_proxy": false,
    "is_hosting": false,
    "is_mobile": false,
    "is_darkweb": false,
    "is_scanner": true,
    "is_snort": true
  },
  "score": {
    "inbound": "Critical",
    "outbound": "Moderate"
  },
  "user_search_count": 0,
  "domain": {
    "count": 0,
    "data": []
  },
  "whois": {
    "count": 0,
    "data": []
  },
  "hostname": {
    "count": 0,
    "data": []
  },
  "ids": {
    "count": 0,
    "data": []
  },
  "vpn": {
    "count": 0,
    "data": []
  },
  "webcam": {
    "count": 0,
    "data": []
  },
  "honeypot": {
    "count": 0,
    "data": []
  },
  "ip_category": {
    "count": 0,
    "data": []
  },
  "port": {
    "count": 0,
    "data": []
  },
  "vulnerability": {
    "count": 0,
    "data": []
  },
  "mobile": {
    "count": 0,
    "data": []
  },
  "status": 200
}
