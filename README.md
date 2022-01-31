
# Endpoint Security Message Analysis Tool - esmat

esmat is a command line tool for macOS that allows you to explore the behavior of Apple's Endpoint Security framework.
By default esmat works like a stop watch: pressing ctrl + t prints statistics for the current interval in which you perform your experiments 
and starts a new interval (can be set to cumulative behavior). 

Possible use cases:
* perform (stress) tests or experiments and use esmat to see whether the recorded events match your expectation or message drops occured
* investigate process behavior: 
   * what child processes are created and how (fork,exec)?
   * which ES messages are created during your experiments?

   
## Usage
Use `./esmat.app/Contents/MacOS/esmat -h` to get all available options and flags with examples:

```
➜ ./esmat.app/Contents/MacOS/esmat -h
Endpoint Security Message Analysis Tool - esmat by ∞ vast limits GmbH

Prints statistics for Endpoint Security messages between two SIGINFO signals (ctrl + t).
Must be run as root to be able to subscribe to Endpoint Security events.

Examples:
sudo ./esmat.app/Contents/MacOS/esmat -a ls git

sudo ./esmat.app/Contents/MacOS/esmat -e NOTIFY_PTY_GRANT NOTIFY_PTY_CLOSE -a sshd

sudo ./esmat.app/Contents/MacOS/esmat -a xpcproxy -pc


Usage: ./esmat.app/Contents/MacOS/esmat [OPTIONS]

Options:
  -h,--help                   Print this help message and exit
  -a,--apps TEXT ...          Add executable names to watch events for.
                              If one or more executable names are specified as arguments,
                              the event types NOTIFY_EXEC, NOTIFY_FORK and NOTIFY_EXIT are automatically enabled.

  -e,--events TEXT ...        Define which ES event types you want to see statistics for.
                              NOTIFY_EXEC, NOTIFY_FORK and NOTIFY_EXIT are automatically enabled
                              if arguments are provided via the -a option.
                              Note: AUTH events are currently not supported.

  -E,--events-available       Prints a list of available Endpoint Security event types.
                              Note: Not all listed events are available on every version of macOS.
                              Only the newest macOS version typically supports all events.

  -p,--parent                 Shows which parent processes have exec'ed into the processes specified via -a.

  -c,--child                  Include child processes which the via -a specified processes exec into.

  -C,--cumulative             If set statistics are never reset between intervals.
```


### Columns of Process Lifecycle Events

| column                |description                                                                              |
|---                    |---                                                                                      |
| `#exec_source_events` | number of messages in which the executable was found as the **source** of an exec       |
| `#exec_target_events` | number of messages in which the executable was found as the **target** of an exec       |
| `#fork_events`        | number of messages for fork events for that executable                                  |
| `#exit_events`        | number of messages for exit events for that executable                                  |
| `delta`               | 0 if the number of "creation events" matches the expected number of exit events. Calculated as *#exec_target* + *#fork* - *#exec_source* - *#exit*  |   


## Prerequisites
There is no need to install anything. However, before you can run the app you need to grant the bundle `Full Disk Access` by dragging it into the list of allowed apps under `Security & Privacy -> Privacy -> Full Disk Access`.
This is a requirement from Apple for every Endpoint Security client. The app won't be able to run without this permission.

   
## Examples

- Investigate process lifecycle events or perform stress tests and evaluate message drops
```
sudo ./esmat.app/Contents/MacOS/esmat -a ls git exa

🚀 ES client statistics #3:
+------------+---------------------+---------------------+--------------+--------------+---------+
| executable | #exec_source_events | #exec_target_events | #fork_events | #exit_events |  delta  |
+------------+---------------------+---------------------+--------------+--------------+---------+
| git        |                  18 |                  36 |            0 |           18 |       0 | ✅
+------------+---------------------+---------------------+--------------+--------------+---------+
| exa        |                   0 |                   1 |            0 |            1 |       0 | ✅
+------------+---------------------+---------------------+--------------+--------------+---------+
| ls         |                   0 |                   3 |            0 |            3 |       0 | ✅
+------------+---------------------+---------------------+--------------+--------------+---------+

+---------------+--------------------+-------------------+
| ES_event_type | #messages_received | #messages_missing |
+---------------+--------------------+-------------------+
| NOTIFY_EXIT   |                248 |                 0 | ✅
+---------------+--------------------+-------------------+
| NOTIFY_FORK   |                255 |                 0 | ✅
+---------------+--------------------+-------------------+
| NOTIFY_EXEC   |                135 |                 0 | ✅
+---------------+--------------------+-------------------+
|        total: |                638 |                 0 | ✅
+---------------+--------------------+-------------------+
⏱ interval duration: 16 seconds
```

- Investigate ES messages and processes for events such as ssh logins

```
sudo ./esmat.app/Contents/MacOS/esmat  -a  sshd -e NOTIFY_PTY_GRANT NOTIFY_PTY_CLOSE -pc

🚀 ES client statistics #2:
+-----------------------+---------------------+---------------------+--------------+--------------+---------+
| executable            | #exec_source_events | #exec_target_events | #fork_events | #exit_events |  delta  |
+-----------------------+---------------------+---------------------+--------------+--------------+---------+
| sshd                  |                   1 |                   1 |            3 |            3 |       0 | ✅
+-----------------------+---------------------+---------------------+--------------+--------------+---------+
| --zsh                 |                   - |                   1 |            - |            - |       - | 🐣
+-----------------------+---------------------+---------------------+--------------+--------------+---------+
| --sshd-keygen-wrapper |                   1 |                   - |            - |            - |       - | 👨‍👩‍👦
+-----------------------+---------------------+---------------------+--------------+--------------+---------+

+------------------+--------------------+-------------------+
| ES_event_type    | #messages_received | #messages_missing |
+------------------+--------------------+-------------------+
| NOTIFY_PTY_CLOSE |                  1 |                 0 | ✅
+------------------+--------------------+-------------------+
| NOTIFY_EXIT      |                115 |                 0 | ✅
+------------------+--------------------+-------------------+
| NOTIFY_PTY_GRANT |                  1 |                 0 | ✅
+------------------+--------------------+-------------------+
| NOTIFY_FORK      |                116 |                 0 | ✅
+------------------+--------------------+-------------------+
| NOTIFY_EXEC      |                 63 |                 0 | ✅
+------------------+--------------------+-------------------+
|           total: |                296 |                 0 | ✅
+------------------+--------------------+-------------------+
⏱ interval duration: 9 seconds
```

## Build
Building requires Xcode 13 or later (C++20) and an Apple developer account. You also need to request the Endpoint Security entitlement from Apple.
Once you received the ES entitlement you can create your provisioning profiles for development and distribution.

To avoid issues with signing and provisioning some configuration options have been offloaded into configuration files.
Once you've cloned the repo you need to create a `Shared.xcconfig`, a `Debug.xcconfig` and optionally a `Release.xcconfig` based on the included template files and fill in the specified values.
This prevents leaking personal information into the repository.

Note: Please do not change these values in the project editor if you want to contribute.

## Dependencies
Uses [CLI11](https://github.com/CLIUtils/CLI11) to build the command line interface.
