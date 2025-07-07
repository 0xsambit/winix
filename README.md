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
- Native Windows ACL (Access Control List) support for accurate permission management
- Windows-specific file system and security model compatibility

### **High Performance Architecture**

- Written in Rust for memory safety and zero-cost abstractions
- Optimized for low resource consumption with minimal dependencies
- Fast startup and execution times
- Efficient system resource monitoring with real-time updates
- Binary size under 5MB for quick deployment

### **Advanced Terminal User Interface (TUI)**

- **Interactive Dashboard**: Multi-tabbed interface with real-time system monitoring
- **Process Management**: Live process list with CPU, memory, and disk I/O statistics
- **System Monitoring**: Hardware sensors, memory usage, and disk space tracking
- **Git Integration**: Repository status, branch information, and commit history
- **File Navigation**: Built-in file browser with directory traversal
- **Command Execution**: Interactive command line within the TUI environment

### **Comprehensive Git Integration**

- **Full Git Passthrough**: Execute any Git command directly through Winix
- **Interactive Git Mode**: Dedicated Git shell for streamlined version control operations
- **Repository Detection**: Automatic Git repository recognition and status display
- **Visual Git Info**: Real-time repository status, branch information, and recent commits in TUI
- **Complete Command Support**: All standard Git operations (clone, add, commit, push, pull, merge, etc.)

### **Extended Unix Command Suite**

- **File Operations**: `chmod` (permissions), `chown` (ownership), `ls`, `cd`, `pwd`
- **System Information**: `uname` (system details), `ps` (processes), `free` (memory), `df` (disk usage)
- **Monitoring Tools**: `uptime` (system uptime), `sensors` (hardware temperatures)
- **Git Version Control**: Complete Git integration with interactive features
- **Extensible Architecture**: Modular design for easy addition of new commands

## Feature Documentation

### Core Unix Commands

Winix provides native Windows implementations of essential Unix/Linux commands with full feature parity and Windows-specific enhancements.

#### File Permission Management - `chmod`

Change file and directory permissions using familiar Unix syntax with Windows ACL integration.

**Usage:**
```bash
chmod [OPTION]... MODE[,MODE]... FILE...
chmod [OPTION]... OCTAL-MODE FILE...
chmod [OPTION]... --reference=RFILE FILE...
```

**Examples:**
| Command | Description |
|---------|-------------|
| `chmod 755 myfile.txt` | Set read/write/execute for owner, read/execute for group and others |
| `chmod u+x script.sh` | Add execute permission for user/owner |
| `chmod -R 644 directory/` | Recursively set read/write for owner, read-only for others |
| `chmod a-w file.txt` | Remove write permission for all users |
| `chmod u=rwx,g=rx,o=r file.txt` | Set specific permissions for user, group, and others |

**Features:**
- ✅ Octal notation support (e.g., 755, 644)
- ✅ Symbolic notation support (e.g., u+x, g-w, a=r)
- ✅ Recursive operations with `-R` flag
- ✅ Windows ACL integration for native permission handling
- ✅ Multiple file support in single command

#### File Ownership Control - `chown`

Modify file and directory ownership using Windows security identifiers.

**Usage:**
```bash
chown [OWNER][:[GROUP]] FILE...
```

**Examples:**
| Command | Description |
|---------|-------------|
| `chown user file.txt` | Change file owner to 'user' |
| `chown user:group file.txt` | Change owner to 'user' and group to 'group' |
| `chown :group file.txt` | Change only the group ownership |

**Features:**
- ✅ Windows user account integration
- ✅ Group ownership support
- ✅ Multiple file operations
- ✅ Native Windows security API usage

#### System Information - `uname`

Display comprehensive system information including OS details, hardware specifications, and network interfaces.

**Output includes:**
- **System Details**: OS name, version, kernel information
- **Hardware Info**: CPU architecture, core count, usage statistics  
- **Network Data**: Interface statistics with data transfer metrics
- **Host Information**: System hostname and domain details

#### Process Management - `ps`

Advanced process monitoring with detailed system resource usage.

**Features:**
- **Process List**: PID, name, CPU usage, memory consumption
- **Resource Monitoring**: Disk I/O statistics (read/write bytes)
- **Status Information**: Process state and priority details
- **Performance Data**: Real-time CPU and memory usage
- **Sorting**: Automatic sorting by CPU usage (highest first)
- **Top Processes**: Displays top 25 most resource-intensive processes

#### Memory Management - `free`

Display system memory and swap usage statistics.

**Information Provided:**
- **Physical Memory**: Total, used, and available RAM
- **Swap Space**: Total and used virtual memory
- **Formatted Output**: Human-readable sizes (GB, MB, KB)

#### Disk Usage - `df`

Show disk space usage for all mounted drives and partitions.

**Features:**
- **Drive Information**: All available disk drives
- **Space Statistics**: Total, available, and used space per drive
- **Formatted Display**: Tabular output with aligned columns
- **Human-readable Sizes**: Automatic unit conversion (GB, MB, KB)

#### System Monitoring - `uptime` & `sensors`

**Uptime Command:**
- System boot time and current uptime
- Load averages (1, 5, and 15-minute intervals)
- System performance metrics

**Sensors Command:**
- Hardware temperature monitoring
- Component-specific temperature readings
- Administrative privilege detection for sensor access
- Hardware compatibility notifications

### Git Integration

Winix provides comprehensive Git version control integration with both standard command execution and enhanced interactive features.

#### Standard Git Commands

Execute any Git command directly through Winix with full feature support:

| Command Category | Examples | Description |
|------------------|----------|-------------|
| **Repository Management** | `git init`, `git clone <url>` | Create and clone repositories |
| **File Operations** | `git add .`, `git add <file>` | Stage files for commit |
| **Commit Operations** | `git commit -m "message"` | Record changes to repository |
| **Branch Management** | `git branch`, `git checkout -b new-feature` | Create and switch branches |
| **Remote Operations** | `git push origin main`, `git pull origin main` | Synchronize with remote repositories |
| **History & Status** | `git status`, `git log --oneline` | View repository state and history |
| **Advanced Operations** | `git merge`, `git diff`, `git reset`, `git stash` | Complex Git workflows |

#### Interactive Git Mode

Access a dedicated Git shell for streamlined operations:

```bash
git --interactive
```

**Interactive Mode Features:**
- **Simplified Commands**: Execute Git commands without the 'git' prefix
- **Persistent Session**: Maintain context across multiple commands
- **Enhanced Prompts**: Visual indicators for Git operations
- **Quick Exit**: Type 'exit' or 'quit' to return to main interface

**Example Interactive Session:**
```
git> status
git> add .
git> commit -m "Update feature"
git> push origin main
git> exit
```

#### TUI Git Integration

The Terminal User Interface provides visual Git repository information:

- **Repository Status**: Clean/dirty working tree indicators
- **Branch Information**: Current branch display with status
- **Recent Commits**: Visual commit history with author and message details
- **Quick Commands**: Press 'c' for instant Git command access
- **Real-time Updates**: Automatic refresh of Git status information

### Terminal User Interface (TUI)

Winix features a sophisticated Terminal User Interface that transforms command-line interaction into an intuitive, graphical experience.

#### Navigation & Controls

| Key Combination | Action |
|-----------------|--------|
| **Tab/Arrow Keys** | Navigate between tabs and interface elements |
| **H** | Toggle help panel with complete key bindings |
| **C** | Enter command mode for direct command execution |
| **Q** | Quit application |
| **Enter** | Execute selected command or confirm action |

#### Dashboard Tabs

The TUI organizes system information into focused tabs:

1. **System Tab**: OS information, CPU details, and hardware specifications
2. **Processes Tab**: Real-time process list with resource usage
3. **Memory Tab**: RAM and swap usage with visual indicators
4. **Disks Tab**: Storage information and disk space utilization
5. **Sensors Tab**: Hardware temperature monitoring
6. **Files Tab**: Interactive file browser with directory navigation
7. **Git Tab**: Repository information, status, and commit history

#### Interactive Features

**Real-time Monitoring:**
- Automatic refresh of system statistics
- Live process and resource updates
- Dynamic memory and CPU usage indicators

**Command Execution:**
- Integrated command line within TUI
- Command history and output display
- Support for all Winix commands within the interface

**File Management:**
- Directory traversal with keyboard navigation
- File listing with detailed information
- Integration with file operation commands

**Git Visualization:**
- Repository status with clean/dirty indicators
- Branch information and switching capabilities
- Recent commit display with metadata
- Working tree status visualization

### Advanced Features

#### Architecture Benefits

**Memory Safety:**
- Rust's ownership system prevents memory leaks and buffer overflows
- Zero-cost abstractions for optimal performance
- Safe concurrency for responsive user interface

**Windows Integration:**
- Native Windows API usage for accurate system information
- Windows security model integration for file operations
- No external dependencies or virtualization overhead

**Extensibility:**
- Modular command structure for easy feature additions
- Plugin architecture foundation for custom commands
- Consistent interface patterns across all utilities

#### Performance Characteristics

| Metric | Specification |
|--------|---------------|
| **Binary Size** | < 5MB |
| **Startup Time** | < 100ms |
| **Memory Usage** | < 10MB at runtime |
| **CPU Impact** | Minimal background processing |
| **Disk I/O** | Optimized for minimal file system access |

#### Deployment Options

**CLI Mode:**
```bash
winix --cli    # Force command-line interface
```

**TUI Mode (Default):**
```bash
winix          # Launch with Terminal User Interface
```

**Command Execution:**
```bash
winix <command> [args]    # Direct command execution
```

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

### Quick Start

**Launch TUI Mode (Default):**
```bash
winix
```

**Use CLI Mode:**
```bash
winix --cli
```

**Execute Direct Commands:**
```bash
winix uname          # System information
winix ps             # Process list  
winix git status     # Git repository status
```

## Project Structure

The project follows a modular architecture with each command implemented as a separate module:

```
src/
├── main.rs         # Application entry point and CLI interface
├── tui.rs          # Terminal User Interface implementation
├── chmod.rs        # File permission management
├── chown.rs        # File ownership operations
├── uname.rs        # System information utilities
├── ps.rs           # Process management and monitoring
├── git.rs          # Git version control integration
├── free.rs         # Memory usage monitoring
├── df.rs           # Disk space utilities
├── uptime.rs       # System uptime and load monitoring
├── sensors.rs      # Hardware temperature monitoring
└── cd.rs           # Directory navigation utilities
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

| Component                   | Technology/Specification              |
| --------------------------- | ------------------------------------- |
| **Core Language**           | Rust 2021 Edition                    |
| **User Interface**          | Terminal UI (TUI) with CLI fallback  |
| **Minimum Windows Version** | Windows 10 (1903+)                   |
| **Architecture Support**    | x86_64                                |
| **Dependencies**            | Minimal external crates               |
| **Binary Size**             | < 5MB                                 |
| **Runtime Memory**          | < 10MB typical usage                  |
| **Git Integration**         | Full passthrough + interactive mode   |
| **Command Count**           | 12+ Unix commands implemented         |
| **Windows API Integration** | Native ACL, Security, Process APIs    |

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for complete details.

---

<div align="center">

**Built with ❤️ using Rust**

[Report Bug](https://github.com/0xsambit/winix/issues) • [Request Feature](https://github.com/0xsambit/winix/issues) • [Documentation](https://github.com/0xsambit/winix/wiki)

</div>
