# Winix

<div align="center">

![Platform](https://img.shields.io/badge/platform-Windows-blue)
![Language](https://img.shields.io/badge/language-Rust-orange)
![License](https://img.shields.io/badge/license-MIT-green)
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

---

## 🚀 Welcome to Winix

Winix is a cross-platform command-line application designed to bridge the gap between Unix/Linux and Windows environments. Built with Rust for optimal performance and reliability, it provides native implementations of essential Unix commands that Windows users frequently need.

---

## 📦 Key Features

- **Native Windows Integration:** Direct Windows API integration, no WSL required.
- **High Performance:** Rust-based, optimized for speed and low resource usage.
- **Async/Await Support:** Modern async programming with Tokio runtime for efficient I/O operations.
- **Stream Processing:** Real-time data processing with Rust's Stream trait for memory-efficient operations.
- **User Experience:** Colorized output, consistent CLI, Windows-compatible paths.
- **Comprehensive Command Suite:** Includes `chmod`, `chown`, `uname`, `ps`, `cat`, `grep`, `head`, `tail`, and more.
- **Command Pipelines:** Chain multiple commands together for complex data processing workflows.
- **Extensible Architecture:** Easily add new commands and features.

### Linux-First Commands Added

The latest command set includes these Linux-first utilities:

- `wc`
- `gzip`
- `zcat`
- `nice`
- `renice`
- `lsof`
- `ip`
- `ulimit`
- `mount`
- `umount`

Platform behavior:

- On Unix/Linux targets, commands execute their functional path.
- On Windows, Linux-specific commands print a clear unsupported/fallback message.

---

## 🏗️ Project Structure

```text
src/
├── main.rs         # Application entry point and CLI interface
├── cat.rs          # File concatenation with async streams
├── grep.rs         # Pattern matching with async processing
├── head.rs         # First N lines with async streams
├── tail.rs         # Last N lines with async processing
├── pipeline.rs     # Async command pipeline system
├── chmod.rs        # File permission management
├── chown.rs        # File ownership operations
├── uname.rs        # System information utilities
├── ps.rs           # Process management tools
└── ...             # Additional command modules
```

---

## ⚡ Quick Start

### Build from Source

```powershell
git clone https://github.com/0xsambit/winix.git
cd winix
cargo build --release
```

### Using Async Commands

Winix now supports async/await for high-performance file operations:

```rust
// Async file concatenation
let result = cat_async_to_string(vec!["file1.txt", "file2.txt"]).await?;

// Async pattern matching
let matches = grep_async_to_string("pattern", vec!["file.txt"]).await?;

// Async head/tail operations
let first_lines = head_async_to_string(vec!["file.txt"], 10).await?;
let last_lines = tail_async_to_string(vec!["file.txt"], 10).await?;

// Command pipelines
let pipeline = CatGrepPipeline::new(
    vec!["file.txt".to_string()],
    "pattern".to_string(),
);
let result = execute_pipeline(pipeline).await?;
```

---

## 🤝 How to Contribute -

### Check - [Discussions](https://github.com/0xsambit/winix/discussions) before going forward

We welcome all contributions! Whether you're fixing bugs, adding features, improving documentation, or helping others, your input is valued.

### Step-by-Step Contribution Guide

1. **Fork the Repository**
     - Click the "Fork" button on GitHub to create your own copy.
2. **Clone Your Fork**
     - `git clone https://github.com/<your-username>/winix.git`
3. **Create a Branch**
     - `git checkout -b feature/your-feature-name`
4. **Make Changes**
     - Implement your feature or fix in the appropriate module.
     - Follow the code style and formatting standards (see below).
     - Run `cargo run`
5. **Test Your Changes**
     - Run `cargo test` to ensure all tests pass.
6. **Commit and Push**
     - `git add .`
     - `git commit -m "Add <feature/fix>"`
     - `git push origin feature/your-feature-name`
7. **Open a Pull Request**
     - Go to your fork on GitHub and click "New Pull Request".
     - Fill in a clear description of your changes.
8. **Respond to Reviews**
     - Address feedback and make necessary updates.

Most importantly, create a upstream to the main branch of the repo, and pull all the changes as soon as the main branch updates. If any PR causes any wrong change in any other part, than what was pushed, it will be immediately revoked and no further points will be given.

### Code Style & Standards

- Use Rust 2021 Edition.
- Write clear, concise, and well-documented code.
- Add tests for new features.
- Keep external dependencies minimal.
- For async features, use Tokio runtime and follow async/await best practices.

### Issue Reporting

- Firstly, use the [Github Discussions](https://github.com/0xsambit/winix/discussions) to discuss which issues to work on and talk about the features or any questions about the project. Everything related to the project has to be first address in the discussions under appropriate category, only after then issues will be assigned.
- Use [GitHub Issues](https://github.com/0xsambit/winix/issues) for bugs, feature requests, and questions.
- Provide detailed steps to reproduce bugs.
- It is important to note that if the PA doesn't assign an issue to you, and you complete the PR, it will still be accepted ( if it is correct ) , but no points will be given

---

## 🙌 Why Contribute?

Contributing to Winix means helping build a tool that empowers Windows users with powerful Unix-like capabilities. Your work will:

- Help bridge OS gaps for developers and sysadmins.
- Improve open-source software for a global audience.
- Grow your Rust and systems programming skills.
- Connect you with a passionate, collaborative community.

---

## 🆘 Getting Help -

### Check [Guidlines](https://github.com/0xsambit/winix/blob/master/CONTRIBUTION.md)

If you need help:

- Check the [Winix Wiki](https://github.com/0xsambit/winix/wiki) for documentation and guides.
- Ask questions or start discussions in [GitHub Issues](https://github.com/0xsambit/winix/issues).
- Tag maintainers or contributors for specific queries.

---

## 📜 Code of Conduct

We are committed to fostering a welcoming and inclusive environment. Please read our [Code of Conduct](https://github.com/0xsambit/winix/blob/main/CODE_OF_CONDUCT.md) before participating. Respectful, constructive communication is expected from all contributors.

---

## 👥 Maintainers & Contact

- **Project Lead:** [@0xsambit](https://github.com/0xsambit)
- **Maintainers:** See [Contributors](https://github.com/0xsambit/winix/graphs/contributors)
- For direct contact, open an issue or email via GitHub profile.

---

## 👤 Contributors

Thanks to everyone who has contributed to Winix!

<!-- Contributors badge (auto-updating) -->

[![Contributors](https://img.shields.io/github/contributors/0xsambit/winix?style=for-the-badge)](https://github.com/0xsambit/winix/graphs/contributors)

<!-- Contributors avatars (auto-updating) -->
<p align="left">
  <a href="https://github.com/0xsambit/winix/graphs/contributors">
    <img src="https://contrib.rocks/image?repo=0xsambit/winix" alt="Contributors" />
  </a>
</p>

See the full list of contributors and their contributions on the [GitHub Contributors Graph](https://github.com/0xsambit/winix/graphs/contributors).

---

## 🌱 New to Open Source?

If you're just getting started with open source, we're here to help!

- Raise a concern or ask for guidance by opening an issue with the `question` or `help wanted` label.
- Connect with maintainers or experienced contributors via GitHub Issues or Discussions.
- Request a mentor or pairing session—just mention it in your issue.
- Check the [Wiki](https://github.com/0xsambit/winix/wiki) for beginner-friendly resources.

Everyone is welcome, and no question is too basic. We want to help you grow as a contributor!

---

## 🌐 Collaboration & Community

- Join discussions in [GitHub Issues](https://github.com/0xsambit/winix/issues) and [Winix Wiki](https://github.com/0xsambit/winix/wiki).
- Connect with other contributors and share ideas.
- Participate in community calls and events (announced in Issues).
- Respectful, inclusive communication is expected.

---

## 🛣️ Roadmap

- **Extended Command Set:** More Unix utilities with async support.
- **Advanced Stream Processing:** Real-time data transformation pipelines.
- **Configuration Management:** User-customizable behavior.
- **Plugin Architecture:** Third-party extensions.
- **Cross-Platform Support:** Linux and macOS expansion.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with ❤️ using Rust**

[Report Bug](https://github.com/0xsambit/winix/issues) • [Request Feature](https://github.com/0xsambit/winix/issues) • [Documentation](https://github.com/0xsambit/winix/wiki)

</div>
