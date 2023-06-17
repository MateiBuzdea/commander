# Commander

Commander is a Python command-line utility for managing reverse shell connections.

## Features

Commander manages multiple reverse shell connections at once by keeping them alive in the background and allowing the user to switch between them.

The program currently provides support only for Linux platforms, such as uploading/downloading files and automatic shell upgrade.

When Ctrl+C is hit, the \x03 byte is sent through the socket rather than stopping the execution of the Commander, thus killing the program that is running on the remote host. This makes interacting with targets and running remote scripts easier. Ctrl+C behaves as expected if no interactive terminal is opened. The interaction can be paused if Ctrl+Z is pressed.

## Installation

The script can be used as a standalone program on any Linux platform.

```bash
git clone https://github.com/MateiBuzdea/commander.git
cd commander
pip install -r requirements.txt
```

## Usage

```bash
./commander.py
```

## Options

| Command | Usage |
| --- | --- |
| help [*command*] | Show help. |
| listen [*ip*:]*port* | Listens on the specific port in the background. |
| listeners | Displays the active listening ports. |
| sessions [*id*] | Displays information about the active sessions. If the id parameter is provided, that session is selected and any further actions will apply to that session. If id is 0, the session is unselected. |
| history *file_path* | Creates a history file with the given path. All the commands run in the interactive terminal of the session will be saved there. |
| shell | Connects with the interactive shell of the selected session. To stop the interaction, use Ctrl+Z. |
| upgrade | Attempts to upgrade the remote shell to a pty-coloured one. Available only for Linux hosts that have Python installed. |
| download *remote_file* *local_path* | Download a remote file to the local machine. |
| upload *local_file* *remote_path* | Upload a local file to the remote path. |
| cwd | Displays the current working directory. |
| lcd *path* | Changes the current working directory to path.|
| kill *id* | Kills the session with the provided id. |
| run *command* | Runs a command on the local machine. |
| netstat | Runs netstat on the local machine. |
| exit | Exits the program. |


## TODO

* Improve OS detection.
* Add file upload/download support for Windows.
* Improve upload/download payloads.
* Improve broken pipe detection and socket error handling.