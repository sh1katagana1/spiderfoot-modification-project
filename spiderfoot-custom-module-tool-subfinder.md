# Spiderfoot Custom Module - Tool Subfinder

***

## Goal
To make a Spiderfoot module that calls on the tool Subfinder from its Docker container and run it against a domain name. This will then produce subdomains

## Setup
First, install Subfinder in Docker:
```
docker pull projectdiscovery/subfinder
```

## Script
Create sfp_tool_subfinder.py
```
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT

from spiderfoot import SpiderFootPlugin, SpiderFootEvent
import subprocess
import json


class sfp_tool_subfinder(SpiderFootPlugin):

    meta = {
        "name": "Subfinder",
        "summary": "Enumerate subdomains using ProjectDiscovery Subfinder.",
        "flags": ["tool", "subdomain", "passive"],
        "useCases": ["Footprint", "Investigate"],
        "categories": ["DNS"]
    }

    opts = {
        "docker_image": "projectdiscovery/subfinder",
        "all_sources": True,
        "timeout": 300
    }

    optdescs = {
        "docker_image": "Docker image to execute.",
        "all_sources": "Use -all.",
        "timeout": "Execution timeout (seconds)."
    }

    def watchedEvents(self):
        return [
            "DOMAIN_NAME"
            
        ]

    def producedEvents(self):
        return [
            "INTERNET_NAME"
        ]

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = set()

        for opt in userOpts:
            self.opts[opt] = userOpts[opt]

    def handleEvent(self, event):

        target = event.data.lower()

        if target in self.results:
            return

        self.results.add(target)

        cmd = [
            "docker",
            "run",
            "--rm",
            self.opts["docker_image"],
            "-d",
            target,
            "-json"
        ]

        if self.opts["all_sources"]:
            cmd.append("-all")

        self.debug(f"Running: {' '.join(cmd)}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=int(self.opts["timeout"])
            )
        except Exception as e:
            self.error(f"Subfinder execution failed: {e}")
            return

        if proc.returncode != 0:
            self.error(proc.stderr)
            return

        seen = set()

        for line in proc.stdout.splitlines():
            if not line.strip():
                continue

            try:
                item = json.loads(line)
            except Exception:
                continue

            host = item.get("host")
            source = item.get("source", "subfinder")

            if not host:
                continue

            host = host.lower()

            if host in seen:
                continue

            seen.add(host)

            evt = SpiderFootEvent(
                "INTERNET_NAME",
                host,
                self.__name__,
                event
            )

            evt.sourceEvent = event

            self.notifyListeners(evt)

            self.info(f"Found {host} ({source})")
```

## Script explanation
### Imports
```
from spiderfoot import SpiderFootPlugin, SpiderFootEvent
import subprocess
import json
```
Every Python file begins by importing code from other libraries.
```
from spiderfoot import SpiderFootPlugin
```
This is the base class that every SpiderFoot module inherits from. Think of it as: "Give me everything a SpiderFoot plugin needs." Without it, SpiderFoot wouldn't know your class is a plugin.
```
from spiderfoot import SpiderFootEvent
```
SpiderFoot communicates using events. For example:
```
DOMAIN_NAME
example.com
```
or
```
IP_ADDRESS
1.1.1.1
```
or
```
EMAILADDR
john@example.com
```
Whenever your module discovers something, it wraps it in a SpiderFootEvent. For example:
```
SpiderFootEvent(
    "INTERNET_NAME",
    "mail.example.com",
    ...
)
```
Then we have subprocess:
```
import subprocess
```
Python cannot directly run Docker commands. subprocess lets Python execute shell commands. Instead of typing:
```
docker run projectdiscovery/subfinder ...
```
your script runs it automatically. 

Then we have JSON. When I formulated the command to run I included -json which is a switch in Subfinder to output the results in json.
```

{
  "host":"app.example.com",
  "source":"hackertarget"
}
```
Python sees that as plain text, and json.loads() converts it into a Python dictionary.

### Creating the Plugin Class
```
class sfp_tool_subfinder(SpiderFootPlugin):
```
This creates a new class. Think of a class as a blueprint. SpiderFoot loads this class whenever it starts and the name must match the filename. If the file is sfp_tool_subfinder.py the class must be class sfp_tool_subfinder(...)

### Metadata
```
meta = {
    "name": "Subfinder",
    "summary": "...",
    "flags": [...],
    "categories": [...]
}
```
This doesn't affect how the module works.

It tells SpiderFoot:
1. plugin name
2. description
3. category
4. icon/category in the GUI

Think of it as the plugin's profile.

### Options
```
opts = {
    "docker_image": "projectdiscovery/subfinder",
    "all_sources": True,
    "timeout": 300
}
```
These are user-configurable settings which you will see in the UI under Settings. Instead of writing
```
docker run projectdiscovery/subfinder
```
everywhere, we write
```
self.opts["docker_image"]
```
which equals
```
projectdiscovery/subfinder
```
If later you want another image, like mycompany/subfinder, you only change one option.


### Option Descriptions
```
optdescs = {
    ...
}
```
These are just descriptions shown in the SpiderFoot GUI. No logic happens here.


### watchedEvents()
```
def watchedEvents(self):
    return [
        "DOMAIN_NAME",
        
    ]
```
It tells SpiderFoot: "Only send me these event types." Imagine another SpiderFoot module produced the event:
```
EMAILADDR
```
These produced events would trigger any activated modules that are "Watching" for that event type. Should your module run? No, because its an Email Address and not a Domain Name, so it ignores it. If SpiderFoot finds
```
DOMAIN_NAME
example.com
```
your module runs because it was looking for that. The reason we dont watch for INTERNET_NAME, is because Spiderfoot lumps subdomains under this event type. So, example.com is a DOMAIN_NAME (Apex domain) and test.example.com is an INTERNET_NAME (Subdomain). You will see in the next section that Spiderfoot takes in an Apex domain and produces INTERNET_NAME (subdomains). If we were also watching for INTERNET_NAME, everytime it found a subdomain, it would then kick the Docker off again for that subdomain, which increases the time of the scan tremendously and is completely unnecessary. 

### producedEvents()
```
def producedEvents(self):
    return [
        "INTERNET_NAME"
    ]
```
As mentioned above, the module itself produces some kind of output, subdomain, phone number, email address, etc. The Subfinder module ONLY produces subdomains. As Spiderfoot lumps these under INTERNET_NAME, that is what event is being produced by Subfinder. If you have another module activated alongside Subfinder, once Subfinder produces that INTERNET_NAME and the other module is "Watching" for INTERNET_NAME, then that module will kick off. 


### Setup
```
def setup(self, sfc, userOpts=dict()):
```
This is called once when SpiderFoot loads the module. It initializes variables.
```
self.sf = sfc
```
Stores the SpiderFoot controller.
```
self.results = set()
```
Creates an empty set. Initially shown as
```
{}
```
As domains are processed:
```
{
    "example.com",
    "google.com"
}
```
This prevents duplicate work. Then:
```
for opt in userOpts:
    self.opts[opt] = userOpts[opt]
```
If the user changed settings in the GUI, for example:
```
timeout = 600
```
those values replace the defaults. 

### handleEvent()
This is the heart of the plugin. Whenever SpiderFoot gives your module an event, this function runs. Example:
```
DOMAIN_NAME
example.com
```
Then we get the target:
```
target = event.data.lower()
```
Suppose the event contains
```
Example.COM
```
we will convert it to
```
example.com
```
Everything becomes lowercase, which is what .lower() means. next we prevent duplicates
```
if target in self.results:
    return
```
If you've already scanned example.com, don't scan it again. Otherwise:
```
self.results.add(target)
```
Remember you've scanned it. Next we build the Docker command
```
cmd = [
    "docker",
    "run",
    "--rm",
    ...
]
```
Instead of making one long string like docker run --rm projectdiscovery/subfinder ... Python stores it as a list.
```
[
 "docker",
 "run",
 "--rm",
 ...
]
```
subprocess.run() executes this list as a command. Next we move to running Docker:
```
proc = subprocess.run(...)
```
This is equivalent to typing docker run ... in a terminal. The result is stored in 'proc' which contains:
1. stdout
2. stderr
3. returncode

Next we check for errors:
```
if proc.returncode != 0:
```
Linux commands return:
```
0 = success
```
Anything else means something failed. Example:
```
docker not found
```
Or
```
image missing
```
Next we move to reading the JSON. Subfinder prints:
```
{"host":"mail.example.com","source":"crtsh"}
{"host":"vpn.example.com","source":"wayback"}
```
Each line is read:
```
for line in proc.stdout.splitlines():
```
One at a time. It then converts JSON into a Python dictionary:
```
item = json.loads(line)
```
Now 'item' becomes
```
{
    "host": "mail.example.com",
    "source": "crtsh"
}

```

Next we move to extracting the hostname
```
host = item.get("host")
```
That gets:
1. mail.example.com
2. source = item.get("source")
3. crtsh

Next we set it to ignore duplicates. 
```
seen = set()
```
Subfinder may output
1. mail.example.com
2. mail.example.com
3. mail.example.com

This prevents notifying SpiderFoot three times. 

Next we create the Spiderfoot Event. 
```
evt = SpiderFootEvent(
    "INTERNET_NAME",
    host,
    self.__class__.__name__,
    event
)
```
This creates a new event. Think of it like filling out a form:
```
Type:
INTERNET_NAME

Data:
mail.example.com

Found by:
Subfinder module

Parent:
DOMAIN_NAME example.com
```
Lastly, we need to notify all other modules listening for events:
```
self.notifyListeners(evt)
```
This is how modules communicate. Modules run, produce events, and other modules that have watchlists need to be notified that a new event was produced. Your module doesn't know who uses the event. It simply publishes it, and any other module that watches INTERNET_NAME can act on it. This event-driven design is one of SpiderFoot's core ideas and allows modules to work together without being tightly coupled.

## Example Output
This module should make new Internet Name subdomains.
































