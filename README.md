# Winix

<div align="center">

![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Language](https://img.shields.io/badge/language-Rust-orange)
![License](https://img.shields.io/badge/license-MIT-green)
![Release](https://img.shields.io/github/v/release/0xsambit/winix)
![Downloads](https://img.shields.io/github/downloads/0xsambit/winix/total)

**Native Unix Command Implementation for Windows**

A high-performance command-line utility that brings essential Unix/Linux functionality to Windows environments without requiring WSL or virtualization.

```
██     ██ ██ ███    ██ ██ ██   ██
██     ██ ██ ████   ██ ██  ██ ██
██  █  ██ ██ ██ ██  ██ ██   ███
██ ███ ██ ██ ██  ██ ██ ██  ██ ██
 ███ ███  ██ ██   ████ ██ ██   ██
```

</div>


![Screenshot (750)](https://github.com/user-attachments/assets/47c994fc-0937-4840-af18-61b702da76e8)

![Screenshot (754)](https://github.com/user-attachments/assets/7447b0df-1f0a-4d1b-af85-daee694d5341)

## Overview

Winix is a cross-platform command-line application designed to bridge the gap between Unix/Linux and Windows environments. Built with Rust for optimal performance and reliability, it provides native implementations of essential Unix commands that Windows users frequently need.

## Key Features

### **Native Windows Integration**

- Direct Windows API integration without virtualization overhead
- No dependency on Windows Subsystem for Linux (WSL)
- Seamless integration with existing Windows workflows

### **High Performance Architecture**

- Written in Rust for memory safety and zero-cost abstractions
- Optimized for low resource consumption
- Fast startup and execution times

### **Enhanced User Experience**

- Colorized terminal output for improved readability
- Consistent command-line interface across all utilities
- Windows-compatible file path handling

### **Comprehensive Command Suite**

- File permission management (`chmod`)
- Ownership control (`chown`)
- System information retrieval (`uname`)
- Process monitoring (`ps`)
- Git version control integration with full command support
- System monitoring tools (`sensors`, `free`, `uptime`, `df`)
- Directory navigation commands (`cd`, `pwd`, `ls`)
- Extensible architecture for additional commands

### **Advanced Git Integration**

- Native Git command execution through system Git
- Interactive Git mode for complex operations
- Real-time repository status and branch information
- Git status, log, commit, push, pull, and branch management
- Repository detection and branch display in CLI prompt
- Integrated Git panels in TUI interface

### **Modern TUI Interface**

- Beautiful terminal user interface with responsive design
- Multi-tab dashboard (System, Processes, Memory, Disks, Sensors, Files, Git)
- Real-time system monitoring and process information
- Interactive command execution within TUI
- Git repository visualization and management
- File browser with directory navigation
- Context-sensitive help system

## Feature Documentation

### Command Reference

| Command | Description | Usage Examples |
|---------|-------------|----------------|
| **chmod** | Change file permissions | `chmod 755 file.txt`<br>`chmod u+x script.sh`<br>`chmod -R 644 directory/` |
| **chown** | Change file ownership | `chown user file.txt`<br>`chown user:group file.txt`<br>`chown :group file.txt` |
| **uname** | Display system information | `uname` - Show system details |
| **ps** | List running processes | `ps` - Show active processes |
| **sensors** | Show hardware sensors | `sensors` - Display temperature and hardware info |
| **free** | Display memory usage | `free` - Show memory statistics |
| **uptime** | Show system uptime | `uptime` - Display boot time and load |
| **df** | Display disk usage | `df` - Show filesystem disk space usage |
| **cd** | Change directory | `cd /path/to/directory` |
| **pwd** | Print working directory | `pwd` - Show current directory |
| **ls** | List directory contents | `ls` - List files in current directory<br>`ls /path` - List files in specified path |
| **git** | Git version control | `git status`, `git log`, `git add`, `git commit` |
| **help** | Show command help | `help` - Display all available commands |

### Git Integration Features

| Feature | Description | Access Method |
|---------|-------------|---------------|
| **Command Execution** | Execute any Git command through Winix | `git <command> [options]` |
| **Interactive Mode** | Enter dedicated Git command mode | `git --interactive` |
| **Repository Detection** | Automatic Git repository detection | Automatic in CLI prompt and TUI |
| **Branch Information** | Display current branch in prompt | Automatic display when in Git repo |
| **Status Monitoring** | Real-time Git status in TUI | TUI Git tab |
| **Commit History** | View recent commits and log | TUI Git tab or `git log` |
| **Repository Info** | Repository path and status display | TUI Git tab |

#### Supported Git Commands
- **Repository Management**: `init`, `clone`, `remote`
- **File Operations**: `add`, `commit`, `status`, `diff`
- **Branch Operations**: `branch`, `checkout`, `merge`
- **Remote Operations**: `push`, `pull`, `fetch`
- **History**: `log`, `show`, `reflog`
- **Staging**: `stash`, `reset`, `revert`
- **And more**: Full Git command compatibility

### TUI Interface Features

#### Dashboard Tabs

| Tab | Purpose | Features |
|-----|---------|----------|
| **System** | System information overview | OS details, kernel info, architecture, hostname, CPU count |
| **Processes** | Process monitoring | Real-time process list, resource usage |
| **Memory** | Memory usage statistics | RAM usage, available memory, memory breakdown |
| **Disks** | Storage information | Disk space usage, filesystem details, mount points |
| **Sensors** | Hardware monitoring | Temperature sensors, hardware status |
| **Files** | File browser | Directory navigation, file listing, path display |
| **Git** | Git repository management | Repository info, branch status, commit history, working tree status |

#### Interactive Features
- **Navigation**: Tab/Arrow keys for tab switching
- **Command Mode**: Press 'C' to enter interactive command execution
- **Help System**: Press 'H' for context-sensitive help
- **Real-time Updates**: Automatic refresh of system information
- **Responsive Design**: Adapts to terminal size and provides optimal layout

#### Git TUI Panels
- **Repository Information**: Current repository path and status
- **Branch Information**: Active branch with visual indicators
- **Working Tree Status**: Real-time display of modified, staged, and untracked files
- **Recent Commits**: Interactive commit history with details
- **Quick Commands**: Easy access to common Git operations

## Installation

### Binary Release

Download the latest release from the [GitHub Releases](https://github.com/0xsambit/winix/releases) page:

```powershell
# Download and extract the latest release
curl -L -o winix.exe https://github.com/0xsambit/winix/releases/latest/download/winix.exe
```

### Build from Source

```powershell
git clone https://github.com/0xsambit/winix.git
cd winix
cargo build --release
```

## Project Structure

The project follows a modular architecture with each command implemented as a separate module:

```
src/
├── main.rs         # Application entry point and CLI interface
├── chmod.rs        # File permission management
├── chown.rs        # File ownership operations
├── uname.rs        # System information utilities
├── ps.rs           # Process management tools
└── ...             # Additional command modules
```

## Development

### Prerequisites

- Rust 1.70+
- Windows 10+ or Windows Server 2019+

### Testing

```powershell
cargo test
cargo test --release
```

### Contributing

We welcome contributions to expand Winix's functionality. Please refer to our [Contributing Guidelines](CONTRIBUTING.md) for detailed information on:

- Code style and formatting standards
- Pull request submission process
- Issue reporting guidelines

### Roadmap

Future development plans include:

- **Extended Command Set**: Implementation of additional Unix utilities
- **Configuration Management**: User-customizable command behavior
- **Plugin Architecture**: Support for third-party command extensions
- **Cross-Platform Support**: Expansion to Linux and macOS environments

## Technical Specifications

| Component                   | Technology              |
| --------------------------- | ----------------------- |
| **Core Language**           | Rust 2021 Edition       |
| **Minimum Windows Version** | Windows 10 (1903+)      |
| **Architecture Support**    | x86_64                  |
| **Dependencies**            | Minimal external crates |
| **Binary Size**             | < 5MB                   |

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for complete details.

---

<div align="center">

**Built with ❤️ using Rust**

[Report Bug](https://github.com/0xsambit/winix/issues) • [Request Feature](https://github.com/0xsambit/winix/issues) • [Documentation](https://github.com/0xsambit/winix/wiki)

</div>
