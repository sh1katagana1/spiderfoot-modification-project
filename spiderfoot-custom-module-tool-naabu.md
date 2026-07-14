# Spiderfoot Custom Module Tool Naabu

***

## Goal
I want to make a custom Spiderfoot module to use a dockerized version of Naabu from Project Discovery. This will be a port scanner tool

## Inputs
```
docker run -it projectdiscovery/naabu -host example.com -p 80,8080,443,8443,22,3389 -j
docker run -it projectdiscovery/naabu -host 172.66.147.243 -p 80,8080,443,8443,22,3389 -j
```
## Outputs
```
{"host":"example.com","ip":"172.66.147.243","timestamp":"2026-07-14T20:28:16.057206694Z","port":8443,"protocol":"tcp","tls":false}
{"host":"example.com","ip":"172.66.147.243","timestamp":"2026-07-14T20:28:16.057257358Z","port":443,"protocol":"tcp","tls":false}
{"host":"example.com","ip":"172.66.147.243","timestamp":"2026-07-14T20:28:16.057266302Z","port":8080,"protocol":"tcp","tls":false}
{"host":"example.com","ip":"172.66.147.243","timestamp":"2026-07-14T20:28:16.057271387Z","port":80,"protocol":"tcp","tls":false}

{"ip":"172.66.147.243","timestamp":"2026-07-14T20:29:37.001526337Z","port":8080,"protocol":"tcp","tls":false}
{"ip":"172.66.147.243","timestamp":"2026-07-14T20:29:37.001601334Z","port":8443,"protocol":"tcp","tls":false}
{"ip":"172.66.147.243","timestamp":"2026-07-14T20:29:37.001610613Z","port":80,"protocol":"tcp","tls":false}
{"ip":"172.66.147.243","timestamp":"2026-07-14T20:29:37.001617731Z","port":443,"protocol":"tcp","tls":false}
```

## Script
Here is sfp_tool_naabu.py
```
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_naabu
# Purpose:      Scan hosts with ProjectDiscovery Naabu (Docker)
#
# Author:       ChatGPT
#
# -------------------------------------------------------------------------------

import json
import subprocess

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_naabu(SpiderFootPlugin):

    meta = {
        'name': "Naabu Port Scanner",
        'summary': "Identify open TCP ports using ProjectDiscovery Naabu.",
        'flags': ["tool", "safe", "docker"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Crawling and Scanning"]
    }

    opts = {
        "docker_image": "projectdiscovery/naabu",
        "ports": "80,443,8080,8443,22,21,25,53,110,143,445,3306,3389",
        "timeout": 60
    }

    optdescs = {
        "docker_image": "Docker image containing Naabu.",
        "ports": "Comma-separated list of ports to scan.",
        "timeout": "Maximum execution time in seconds."
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = set()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "DOMAIN_NAME",
            "INTERNET_NAME",
            "IP_ADDRESS"
        ]

    def producedEvents(self):
        return [
            "TCP_PORT_OPEN"
        ]

    def handleEvent(self, event):

        eventName = event.eventType
        target = event.data

        if target in self.results:
            self.debug(f"Already scanned {target}")
            return

        self.results.add(target)

        cmd = [
            "docker",
            "run",
            "--rm",
            self.opts["docker_image"],
            "-host",
            target,
            "-p",
            self.opts["ports"],
            "-j"
        ]

        self.info(f"Running Naabu against {target}")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.opts["timeout"]
            )
        except subprocess.TimeoutExpired:
            self.error(f"Naabu timed out scanning {target}")
            return
        except Exception as e:
            self.error(f"Unable to execute Naabu: {e}")
            return

        if proc.returncode != 0:
            self.error(proc.stderr)
            return

        if not proc.stdout:
            self.debug(f"No ports discovered for {target}")
            return

        for line in proc.stdout.splitlines():

            line = line.strip()

            if not line:
                continue

            try:
                result = json.loads(line)
            except Exception:
                self.debug(f"Skipping invalid JSON: {line}")
                continue

            port = result.get("port")
            

            if not port:
                continue

            data = str(port)

            evt = SpiderFootEvent(
                "TCP_PORT_OPEN",
                data,
                self.__class__.__name__,
                event
            )

            self.notifyListeners(evt)
```

## Script Breakdown
### Imports
```
import json
import subprocess

from spiderfoot import SpiderFootEvent, SpiderFootPlugin
```
This loads the tools your module needs. For 'json' Naabu outputs JSON because you run it with: -j. Example Naabu output:
```
{
 "ip":"172.66.147.243",
 "port":443,
 "protocol":"tcp"
}
```
Python cannot directly understand that text, so the json library converts it into a Python object. Example:
```
result = json.loads(line)
```
turns:
```
{"port":443}
```
into:
```
{
    "port": 443
}
```
Now Python can access:
```
result.get("port")
```

For the subprocess import, this allows Python to run external programs. Your module needs to execute:
```
docker run --rm projectdiscovery/naabu ...
```
Python cannot run Docker by itself, so we use:
```
subprocess.run()
```
For the SpiderFoot imports
```
from spiderfoot import SpiderFootEvent, SpiderFootPlugin
```
These are SpiderFoot's own classes, like SpiderFootPlugin. Your module is a SpiderFoot plugin, so your class must inherit from it. For SpiderFootEvent, This creates events that SpiderFoot understands. Example:
```
TCP_PORT_OPEN
443
```

### Create the module class
```
class sfp_tool_naabu(SpiderFootPlugin):
```
This creates your actual SpiderFoot module. The name matters as it needs to be the name from your script name. SpiderFoot expects modules to follow this style:
```
sfp_<type>_<name>
```
Examples:
```
sfp_tool_nmap
sfp_tool_masscan
sfp_tool_naabu
```
The part: (SpiderFootPlugin) means: "Make this class behave like a SpiderFoot module."

### Module metadata
```
meta = {
    'name': "Tool - Naabu",
    'summary': "Identify open TCP ports using ProjectDiscovery Naabu.",
    'flags': ["tool", "slow", "invasive"],
    'useCases': ["Footprint", "Investigate"],
    'categories': ["Crawling and Scanning"],
```
Be aware that it is specific what name you put for categories. If it doesn't match one that Spiderfoot is expecting it will throw an error. I just grabbed the one from the default sfp_tool_nmap.py module. For:
```
'flags': ["tool", "slow", "invasive"],
```
These describe the module.
1. tool - Means: "This module runs an external program."
2. slow - Port scanning takes longer than passive lookups.
3. invasive - Port scanning sends traffic to the target.

### Module options
```
opts = {
    "docker_image": "projectdiscovery/naabu",
    "ports": "80,443,8080,8443,22,21",
    "timeout": 60
}
```
These are configurable settings in the UI under Settings. Instead of hardcoding values everywhere, we store them here. Example:
```
self.opts["ports"]
```
returns:
```
80,443,8080,8443,22,21
```

### Option descriptions
```
optdescs = {
    "docker_image": "Docker image containing Naabu.",
    "ports": "Comma-separated list of ports to scan.",
    "timeout": "Maximum execution time."
}
```
These are descriptions shown in SpiderFoot UI.

### Setup function
```
def setup(self, sfc, userOpts=dict()):
```
SpiderFoot calls this when loading the module. 

### Store SpiderFoot connection
```
self.sf = sfc
```
This gives your module access to SpiderFoot functions.

### Track already scanned targets
```
self.results = set()
```
A set stores unique values. Example:
```
example.com
172.66.147.243
```
This prevents scanning the same target repeatedly.

### Load user settings
```
for opt in userOpts.keys():
    self.opts[opt] = userOpts[opt]
```
If the user changes options in SpiderFoot, this updates them.

### Watched Events
```
def watchedEvents(self):
    return [
        "DOMAIN_NAME",
        "INTERNET_NAME",
        "IP_ADDRESS"
    ]
```
Every Spiderfoot module produces events and every module listens for these produced events. These watchedEvents can also come from the input you give a New Scan. If your input is example.com, this is a DOMAIN_NAME and an INTERNET_NAME. If Naabu is activated for the scan, it has these two events in its WatchEvents list and the module will kick off when it sees these. If another module you have activated produces a domain name (apex domain), internet name (subdomain), or IP Address, that will also kick off the Naabu module.

### Produced Events
```
def producedEvents(self):
    return [
        "TCP_PORT_OPEN"
    ]
```
The only result Naabu will produce is an open tcp port, or TCP_PORT_OPEN. Now other activate modules can consume the ports found by Naabu and enrich them. 

### Handle Event
```
def handleEvent(self, event):
````
This is the meat of the module, it's where everything happens. 

### Get the target
```
target = event.data
```
Example, SpiderFoot gives: example.com. Now: target contains: example.com

### Prevent duplicate scans
```
if target in self.results:
    return

self.results.add(target)
```
Example, SpiderFoot discovers: example.com. The Module scans it. Later another module discovers: example.com. The scan is skipped.

### Build the Docker command
```
cmd = [
    "docker",
    "run",
    "--rm",
    self.opts["docker_image"],
    "-host",
    target,
    "-p",
    self.opts["ports"],
    "-j"
]
```
This becomes:
```
docker run --rm projectdiscovery/naabu \
-host example.com \
-p 80,443,8080,8443 \
-j
```
The Python list is just another way of building a command.

### Run Naabu
```
proc = subprocess.run(
    cmd,
    capture_output=True,
    text=True,
    timeout=self.opts["timeout"]
)
```
This executes Docker. The results go into:
```
proc.stdout
```
Example:
```
{"port":443}
{"port":80}
```

### Read each JSON result
```
for line in proc.stdout.splitlines():
```
Naabu returns multiple lines:
```
port 443
port 80
port 8080
```
This processes them one at a time.

### Convert JSON into Python
```
result = json.loads(line)
```
This turns:
```
{"port":443}
```
into:
```
{
 "port":443
}
```

### Extract the port
```
port = result.get("port")

if not port:
    continue

data = str(port)
```
Example, Naabu returns:
```
{
"port":443
}
```
Python creates:
```
data = "443"
```
Instead of 1.1.1.1:443

### Create the SpiderFoot event
```
evt = SpiderFootEvent(
    "TCP_PORT_OPEN",
    data,
    self.__class__.__name__,
    event
)
```
This creates:
```
Event Type:
TCP_PORT_OPEN

Data:
443

Source:
sfp_tool_naabu
```

### Send it back to SpiderFoot
```
self.notifyListeners(evt)
```
This tells SpiderFoot that it's found open ports and has produced an event of TCP_PORT_OPEN in case any other modules are listening for this event.

## Expected results
If it finds any open ports, it will list just the port number. 
