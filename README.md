# Agent Smith

## Description

Simple python monitoring tool.

## Installation

Git clone project :
```
$ git clone https://github.com/hvad/agent-smith.git 
```

In a python 3.10 virtual environnement install requirements :

```
$ pip install -r requirements.txt
```

## Usage

Create configuration file :

```
$ python agent-smith.py -c agent-smith.ini -g
```

Execute script like below in daemon mode : 
```
$ python agent-smith.py -d -c agent-smith.ini
```

Execute command like below to have help :
```
$ python agent-smith.py -h
usage: agent-smith.py [-h] [-d] -c CONFIG [-g]

Agent Smith Daemon

options:
  -h, --help            show this help message and exit
  -d, --daemonize       Daemonize the process
  -c CONFIG, --config CONFIG
                        Path to the configuration file
  -g, --generate_config
                        Generate configuration file
                                                     
```

## Authors and acknowledgment
