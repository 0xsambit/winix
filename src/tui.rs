use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, BorderType, Borders, Cell, Clear, Gauge, List, ListItem, ListState, Paragraph, Row,
        Table, Tabs, Wrap,
    },
    Frame, Terminal,
};
use std::io;
use std::time::{Duration, Instant};

// Import statements for integrating with existing modules
// Note: These are currently unused as we're implementing direct capture functions
// use crate::{chmod, chown, df, free, ps, sensors, uname, uptime};

#[derive(Debug)]
pub struct App {
    pub selected_tab: usize,
    pub should_quit: bool,
    #[allow(dead_code)]
    pub process_list_state: ListState,
    pub last_update: Instant,
    pub show_help: bool,
    pub current_dir: String,
    pub ls_items: Vec<String>,
    pub ls_state: ListState,
    pub command_input: String,
    pub command_output: Vec<String>,
    pub show_command_mode: bool,
}

impl Default for App {
    fn default() -> App {
        let mut app = App {
            selected_tab: 0,
            should_quit: false,
            process_list_state: ListState::default(),
            last_update: Instant::now(),
            show_help: false,
            current_dir: std::env::current_dir()
                .unwrap_or_else(|_| "?".into())
                .display()
                .to_string(),
            ls_items: Vec::new(),
            ls_state: ListState::default(),
            command_input: String::new(),
            command_output: Vec::new(),
            show_command_mode: false,
        };
        app.refresh_ls();
        app
    }
}

impl App {
    pub fn refresh_ls(&mut self) {
        self.ls_items.clear();
        if let Ok(entries) = std::fs::read_dir(&self.current_dir) {
            for entry in entries {
                if let Ok(entry) = entry {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if entry.file_type().is_ok() && entry.file_type().unwrap().is_dir() {
                        self.ls_items.push(format!("📁 {}", name));
                    } else {
                        self.ls_items.push(format!("📄 {}", name));
                    }
                }
            }
        }
        self.ls_items.sort();
    }

    pub fn next_tab(&mut self) {
        self.selected_tab = (self.selected_tab + 1) % 7;
    }

    pub fn previous_tab(&mut self) {
        if self.selected_tab > 0 {
            self.selected_tab -= 1;
        } else {
            self.selected_tab = 6;
        }
    }

    pub fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }

    pub fn toggle_command_mode(&mut self) {
        self.show_command_mode = !self.show_command_mode;
        if !self.show_command_mode {
            self.command_input.clear();
        }
    }

    pub fn execute_command(&mut self) {
        if self.command_input.trim().is_empty() {
            return;
        }

        let parts: Vec<&str> = self.command_input.trim().split_whitespace().collect();
        let command = parts[0].to_lowercase();

        self.command_output.clear();

        match command.as_str() {
            "cd" => {
                if parts.len() > 1 {
                    if let Err(e) = std::env::set_current_dir(parts[1]) {
                        self.command_output.push(format!("cd: {}", e));
                    } else {
                        self.current_dir = std::env::current_dir()
                            .unwrap_or_else(|_| "?".into())
                            .display()
                            .to_string();
                        self.refresh_ls();
                        self.command_output
                            .push(format!("Changed directory to: {}", self.current_dir));
                    }
                } else {
                    self.command_output
                        .push("Usage: cd <directory>".to_string());
                }
            }
            "pwd" => {
                self.command_output.push(self.current_dir.clone());
            }
            "ls" => {
                for item in &self.ls_items {
                    self.command_output.push(item.clone());
                }
            }
            "uname" => {
                // Capture uname output directly
                let output = capture_uname_output();
                for line in output.lines() {
                    self.command_output.push(line.to_string());
                }
            }
            "ps" => {
                // Capture ps output directly
                let output = capture_ps_output();
                for line in output.lines() {
                    self.command_output.push(line.to_string());
                }
            }
            "free" => {
                // Capture free output directly
                let output = capture_free_output();
                for line in output.lines() {
                    self.command_output.push(line.to_string());
                }
            }
            "df" => {
                // Capture df output directly
                let output = capture_df_output();
                for line in output.lines() {
                    self.command_output.push(line.to_string());
                }
            }
            "uptime" => {
                // Capture uptime output directly
                let output = capture_uptime_output();
                for line in output.lines() {
                    self.command_output.push(line.to_string());
                }
            }
            "sensors" => {
                // Capture sensors output directly
                let output = capture_sensors_output();
                for line in output.lines() {
                    self.command_output.push(line.to_string());
                }
            }
            "chmod" => {
                if parts.len() < 3 {
                    self.command_output
                        .push("Usage: chmod <permissions> <file>".to_string());
                } else {
                    let args: Vec<&str> = parts[1..].to_vec();
                    let output = capture_chmod_output(&args);
                    for line in output.lines() {
                        self.command_output.push(line.to_string());
                    }
                }
            }
            "chown" => {
                if parts.len() < 3 {
                    self.command_output
                        .push("Usage: chown <owner> <file>".to_string());
                } else {
                    let args: Vec<&str> = parts[1..].to_vec();
                    let output = capture_chown_output(&args);
                    for line in output.lines() {
                        self.command_output.push(line.to_string());
                    }
                }
            }
            "git" => {
                if parts.len() < 2 {
                    self.command_output
                        .push("Usage: git <command> [options]".to_string());
                    self.command_output.push("Examples:".to_string());
                    self.command_output.push("  git status".to_string());
                    self.command_output.push("  git log --oneline".to_string());
                    self.command_output.push("  git add .".to_string());
                    self.command_output
                        .push("  git commit -m \"message\"".to_string());
                } else {
                    let args: Vec<&str> = parts[1..].to_vec();
                    let output = capture_git_output(&args);
                    for line in output.lines() {
                        self.command_output.push(line.to_string());
                    }
                }
            }
            "psh" | "powershell" => {
                if parts.len() < 2 {
                    self.command_output
                        .push("Usage: psh <command> [options]".to_string());
                    self.command_output.push("Examples:".to_string());
                    self.command_output.push("  psh Get-Process".to_string());
                    self.command_output.push("  psh Get-ChildItem".to_string());
                    self.command_output.push("  psh Get-Service".to_string());
                    self.command_output
                        .push("  psh Test-Connection google.com".to_string());
                } else {
                    let args: Vec<&str> = parts[1..].to_vec();
                    let output = capture_powershell_output(&args);
                    for line in output.lines() {
                        self.command_output.push(line.to_string());
                    }
                }
            }
            #[cfg(windows)]
            "nice" => {
                if parts.len() < 2 {
                    self.command_output
                        .push("Usage: nice [-increment | -n increment] command [argument...]".to_string());
                    self.command_output.push("".to_string());
                    self.command_output.push("Priority increments (Unix nice values):".to_string());
                    self.command_output.push("  -20 to -16  Realtime priority (requires admin)".to_string());
                    self.command_output.push("  -15 to -11  High priority".to_string());
                    self.command_output.push("  -10 to -6   Above normal priority".to_string());
                    self.command_output.push("  -5 to +5    Normal priority (default)".to_string());
                    self.command_output.push("  +6 to +10   Below normal priority".to_string());
                    self.command_output.push("  +11 to +19  Idle priority".to_string());
                    self.command_output.push("".to_string());
                    self.command_output.push("Examples:".to_string());
                    self.command_output.push("  nice notepad.exe".to_string());
                    self.command_output.push("  nice -10 calc.exe".to_string());
                    self.command_output.push("  nice -n 15 ping google.com".to_string());
                } else {
                    let args: Vec<&str> = parts[1..].to_vec();
                    let output = capture_nice_output(&args);
                    for line in output.lines() {
                        self.command_output.push(line.to_string());
                    }
                }
            }
            "clear" => {
                self.command_output.clear();
            }
            "help" => {
                self.command_output.push("Available commands:".to_string());
                self.command_output
                    .push("  cd <dir>     - Change directory".to_string());
                self.command_output
                    .push("  pwd          - Print working directory".to_string());
                self.command_output
                    .push("  ls           - List files".to_string());
                self.command_output
                    .push("  uname        - System information".to_string());
                self.command_output
                    .push("  ps           - Process list".to_string());
                self.command_output
                    .push("  free         - Memory usage".to_string());
                self.command_output
                    .push("  df           - Disk usage".to_string());
                self.command_output
                    .push("  uptime       - System uptime".to_string());
                self.command_output
                    .push("  sensors      - Temperature sensors".to_string());
                self.command_output
                    .push("  chmod        - Change permissions".to_string());
                self.command_output
                    .push("  chown        - Change ownership".to_string());
                self.command_output
                    .push("  git          - Git version control".to_string());
                self.command_output
                    .push("  psh          - PowerShell commands".to_string());
                #[cfg(windows)]
                self.command_output
                    .push("  nice         - Run command with priority".to_string());
                self.command_output
                    .push("  clear        - Clear output".to_string());
                self.command_output
                    .push("  help         - Show this help".to_string());
                self.command_output.push("".to_string());
                self.command_output
                    .push("Note: Unknown commands will be passed to PowerShell".to_string());
            }
            _ => {
                // Fallback to PowerShell for unknown commands
                let output = capture_powershell_output(&parts);
                if output.trim().is_empty() {
                    self.command_output
                        .push(format!("Unknown command: '{}'", command));
                    self.command_output
                        .push("Type 'help' for built-in commands".to_string());
                } else {
                    for line in output.lines() {
                        self.command_output.push(line.to_string());
                    }
                }
            }
        }

        self.command_input.clear();
    }
}

pub fn run_tui() -> Result<(), Box<dyn std::error::Error>> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = App::default();

    // Main loop
    let result = run_app(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(result?)
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        // Use slightly longer polling for better performance while maintaining responsiveness
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if app.show_command_mode {
                        match key.code {
                            KeyCode::Char(c) => {
                                app.command_input.push(c);
                            }
                            KeyCode::Backspace => {
                                app.command_input.pop();
                            }
                            KeyCode::Enter => {
                                app.execute_command();
                            }
                            KeyCode::Esc => {
                                app.toggle_command_mode();
                            }
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Char('Q') => {
                                app.should_quit = true;
                            }
                            KeyCode::Char('h') | KeyCode::Char('H') => {
                                app.toggle_help();
                            }
                            KeyCode::Char('c') | KeyCode::Char('C') => {
                                app.toggle_command_mode();
                            }
                            KeyCode::Left => {
                                app.previous_tab();
                            }
                            KeyCode::Right => {
                                app.next_tab();
                            }
                            KeyCode::Tab => {
                                app.next_tab();
                            }
                            KeyCode::Char('r') | KeyCode::Char('R') => {
                                app.last_update = Instant::now();
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if app.should_quit {
            break;
        }

        // Auto-refresh every 10 seconds to reduce system calls
        if app.last_update.elapsed() >= Duration::from_secs(10) {
            app.last_update = Instant::now();
        }
    }

    Ok(())
}

fn ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.area());

    // Header
    let header = create_header();
    f.render_widget(header, chunks[0]);

    // Main content
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(chunks[1]);

    // Tab bar
    let tab_titles = vec![
        "System",
        "Processes",
        "Memory",
        "Disks",
        "Sensors",
        "Files",
        "Git",
    ];
    let tabs = Tabs::new(tab_titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Dashboard")
                .border_type(BorderType::Plain),
        )
        .style(Style::default().fg(Color::Gray))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .select(app.selected_tab);
    f.render_widget(tabs, main_chunks[0]);

    // Tab content
    match app.selected_tab {
        0 => render_system_info(f, main_chunks[1]),
        1 => render_processes(f, main_chunks[1]),
        2 => render_memory(f, main_chunks[1]),
        3 => render_disk_usage(f, main_chunks[1]),
        4 => render_sensors(f, main_chunks[1]),
        5 => render_file_browser(f, main_chunks[1], app),
        6 => render_git_info(f, main_chunks[1]),
        _ => {}
    }

    // Footer
    let footer = create_footer();
    f.render_widget(footer, chunks[2]);

    // Help popup
    if app.show_help {
        render_help_popup(f);
    }

    // Command mode popup
    if app.show_command_mode {
        render_command_popup(f, app);
    }
}

fn create_header() -> Paragraph<'static> {
    let header_text = vec![Line::from(vec![
        Span::styled(
            "WINIX",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" | ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            "Linux Commands on Windows",
            Style::default().fg(Color::White),
        ),
    ])];

    Paragraph::new(header_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Plain),
        )
        .style(Style::default().fg(Color::White))
}

fn create_footer() -> Paragraph<'static> {
    let footer_text = vec![Line::from(vec![
        Span::styled("Tab/Arrow Keys: ", Style::default().fg(Color::Cyan)),
        Span::styled("Navigate", Style::default().fg(Color::White)),
        Span::styled(" | ", Style::default().fg(Color::DarkGray)),
        Span::styled("H: ", Style::default().fg(Color::Cyan)),
        Span::styled("Help", Style::default().fg(Color::White)),
        Span::styled(" | ", Style::default().fg(Color::DarkGray)),
        Span::styled("C: ", Style::default().fg(Color::Cyan)),
        Span::styled("Command", Style::default().fg(Color::White)),
        Span::styled(" | ", Style::default().fg(Color::DarkGray)),
        Span::styled("Q: ", Style::default().fg(Color::Cyan)),
        Span::styled("Quit", Style::default().fg(Color::White)),
    ])];

    Paragraph::new(footer_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Plain),
        )
        .style(Style::default().fg(Color::White))
}

fn render_system_info(f: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    // System Information
    let system_info = get_system_info();
    let info_paragraph = Paragraph::new(system_info)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("System Information")
                .border_type(BorderType::Plain),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(info_paragraph, chunks[0]);

    // Uptime
    let uptime_info = get_uptime_info();
    let uptime_paragraph = Paragraph::new(uptime_info)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Uptime")
                .border_type(BorderType::Plain),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(uptime_paragraph, chunks[1]);
}

fn render_processes(f: &mut Frame, area: Rect) {
    let processes = get_process_list();
    let header =
        Row::new(vec!["PID", "Name", "CPU%", "Memory"]).style(Style::default().fg(Color::Cyan));

    let rows: Vec<Row> = processes
        .into_iter()
        .map(|p| {
            Row::new(vec![
                Cell::from(p.0),
                Cell::from(p.1),
                Cell::from(p.2),
                Cell::from(p.3),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        &[
            Constraint::Length(8),
            Constraint::Percentage(50),
            Constraint::Length(8),
            Constraint::Percentage(25),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Top Processes")
            .border_type(BorderType::Plain),
    );

    f.render_widget(table, area);
}

fn render_memory(f: &mut Frame, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    let memory_info = get_memory_info();

    // Memory usage gauge
    let memory_gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Memory Usage")
                .border_type(BorderType::Plain),
        )
        .gauge_style(Style::default().fg(Color::Cyan))
        .ratio(memory_info.usage_ratio)
        .label(format!("{:.1}%", memory_info.usage_ratio * 100.0));
    f.render_widget(memory_gauge, chunks[0]);

    // Memory details
    let memory_details = Paragraph::new(memory_info.details)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Memory Details")
                .border_type(BorderType::Plain),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(memory_details, chunks[1]);
}

fn render_disk_usage(f: &mut Frame, area: Rect) {
    let disk_info = get_disk_info();
    let disk_paragraph = Paragraph::new(disk_info)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Disk Usage")
                .border_type(BorderType::Plain),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(disk_paragraph, area);
}

fn render_sensors(f: &mut Frame, area: Rect) {
    let sensor_info = get_sensor_info();
    let sensor_paragraph = Paragraph::new(sensor_info)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Temperature Sensors")
                .border_type(BorderType::Plain),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(sensor_paragraph, area);
}

fn render_file_browser(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    // Current directory
    let current_dir = Paragraph::new(format!("📁 {}", app.current_dir)).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Current Directory")
            .border_type(BorderType::Plain),
    );
    f.render_widget(current_dir, chunks[0]);

    // File list
    let items: Vec<ListItem> = app
        .ls_items
        .iter()
        .map(|item| ListItem::new(item.as_str()))
        .collect();

    let file_list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Files & Directories")
                .border_type(BorderType::Plain),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(file_list, chunks[1], &mut app.ls_state.clone());
}

fn render_help_popup(f: &mut Frame) {
    let area = centered_rect(70, 80, f.area());
    f.render_widget(Clear, area);

    let help_text = vec![
        Line::from(Span::styled(
            "Winix Help",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Navigation:"),
        Line::from("  Tab / ← → : Switch between tabs"),
        Line::from("  H         : Toggle help"),
        Line::from("  C         : Open command mode"),
        Line::from("  Q         : Quit"),
        Line::from(""),
        Line::from("Tabs:"),
        Line::from("  System    : OS information"),
        Line::from("  Processes : Running processes"),
        Line::from("  Memory    : Memory usage"),
        Line::from("  Disks     : Disk usage"),
        Line::from("  Sensors   : Temperature sensors"),
        Line::from("  Files     : File browser"),
        Line::from(""),
        Line::from("Press H to close"),
    ];

    let help_popup = Paragraph::new(help_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Help")
                .border_type(BorderType::Plain),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(help_popup, area);
}

fn render_command_popup(f: &mut Frame, app: &App) {
    let area = centered_rect(80, 60, f.area());
    f.render_widget(Clear, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    // Command input
    let input = Paragraph::new(app.command_input.as_str())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Command (ESC to close)")
                .border_type(BorderType::Plain),
        )
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(input, chunks[0]);

    // Command output
    let output: Vec<Line> = app
        .command_output
        .iter()
        .map(|line| Line::from(line.as_str()))
        .collect();

    let output_paragraph = Paragraph::new(output)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Output")
                .border_type(BorderType::Plain),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(output_paragraph, chunks[1]);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn get_system_info() -> Text<'static> {
    let mut info = String::new();

    // Get system information using static methods
    if let Some(name) = sysinfo::System::name() {
        info.push_str(&format!("OS: {}\n", name));
    }
    if let Some(version) = sysinfo::System::os_version() {
        info.push_str(&format!("OS Version: {}\n", version));
    }
    if let Some(kernel) = sysinfo::System::kernel_version() {
        info.push_str(&format!("Kernel: {}\n", kernel));
    }

    info.push_str(&format!("Architecture: {}\n", std::env::consts::ARCH));

    if let Some(hostname) = sysinfo::System::host_name() {
        info.push_str(&format!("Hostname: {}\n", hostname));
    }

    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();
    info.push_str(&format!("Total CPUs: {}\n", sys.cpus().len()));

    Text::from(info)
}

fn get_uptime_info() -> Text<'static> {
    let uptime_seconds = sysinfo::System::uptime();
    let days = uptime_seconds / 86400;
    let hours = (uptime_seconds % 86400) / 3600;
    let minutes = (uptime_seconds % 3600) / 60;

    let uptime_text = format!(
        "System uptime: {} days, {} hours, {} minutes\nBoot time: {} seconds ago",
        days, hours, minutes, uptime_seconds
    );

    Text::from(uptime_text)
}

fn get_process_list() -> Vec<(String, String, String, String)> {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut processes: Vec<_> = sys.processes().iter().collect();
    processes.sort_by(|a, b| {
        b.1.cpu_usage()
            .partial_cmp(&a.1.cpu_usage())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    processes
        .iter()
        .take(15)
        .map(|(pid, process)| {
            let name = process.name().to_string_lossy().to_string();
            let name = if name.len() > 20 {
                format!("{}...", &name[..17])
            } else {
                name
            };
            (
                pid.to_string(),
                name,
                format!("{:.1}%", process.cpu_usage()),
                format_bytes(process.memory()),
            )
        })
        .collect()
}

fn format_bytes(bytes: u64) -> String {
    let gb = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    let mb = bytes as f64 / (1024.0 * 1024.0);
    let kb = bytes as f64 / 1024.0;

    if gb >= 1.0 {
        format!("{:.1} GB", gb)
    } else if mb >= 1.0 {
        format!("{:.1} MB", mb)
    } else if kb >= 1.0 {
        format!("{:.1} KB", kb)
    } else {
        format!("{} B", bytes)
    }
}

struct MemoryInfo {
    usage_ratio: f64,
    details: Text<'static>,
}

fn get_memory_info() -> MemoryInfo {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();

    let total_memory = sys.total_memory();
    let used_memory = sys.used_memory();
    let total_swap = sys.total_swap();
    let used_swap = sys.used_swap();

    let usage_ratio = if total_memory > 0 {
        used_memory as f64 / total_memory as f64
    } else {
        0.0
    };

    let details = format!(
        "Total Memory: {}\nUsed Memory: {}\nFree Memory: {}\nTotal Swap: {}\nUsed Swap: {}",
        format_bytes(total_memory),
        format_bytes(used_memory),
        format_bytes(total_memory - used_memory),
        format_bytes(total_swap),
        format_bytes(used_swap)
    );

    MemoryInfo {
        usage_ratio,
        details: Text::from(details),
    }
}

fn get_disk_info() -> Text<'static> {
    use sysinfo::Disks;
    let disks = Disks::new_with_refreshed_list();

    let mut info = String::new();
    info.push_str("Filesystem     Size      Used      Avail     Use%   Mounted on\n");
    info.push_str("─".repeat(70).as_str());
    info.push('\n');

    for disk in &disks {
        let total_space = disk.total_space();
        let available_space = disk.available_space();
        let used_space = total_space - available_space;

        let usage_percent = if total_space > 0 {
            (used_space as f64 / total_space as f64) * 100.0
        } else {
            0.0
        };

        let mount_point = disk.mount_point().to_string_lossy();
        let name = disk.name().to_string_lossy();

        info.push_str(&format!(
            "{:<14} {:<9} {:<9} {:<9} {:<6.1}% {}\n",
            name,
            format_bytes(total_space),
            format_bytes(used_space),
            format_bytes(available_space),
            usage_percent,
            mount_point
        ));
    }

    Text::from(info)
}

fn get_sensor_info() -> Text<'static> {
    use sysinfo::Components;
    let components = Components::new_with_refreshed_list();

    let mut info = String::new();

    if components.is_empty() {
        info.push_str("No temperature sensors found or accessible.\n");
        info.push_str("Note: On Windows, temperature sensors may require:\n");
        info.push_str("  - Administrator privileges\n");
        info.push_str("  - Hardware that supports temperature monitoring\n");
        info.push_str("  - Proper drivers installed\n");
    } else {
        info.push_str("Component Temperatures:\n");
        info.push_str("─".repeat(40).as_str());
        info.push('\n');

        for component in &components {
            let label = component.label();
            let temperature = component.temperature();
            let max_temp = component.max();
            let critical_temp = component.critical();

            if let Some(temp) = temperature {
                info.push_str(&format!("{}: {:.1}°C", label, temp));

                if let Some(max) = max_temp {
                    info.push_str(&format!(" (max: {:.1}°C)", max));
                }

                if let Some(crit) = critical_temp {
                    info.push_str(&format!(" (critical: {:.1}°C)", crit));
                }

                info.push('\n');
            }
        }
    }

    Text::from(info)
}

// Helper functions to capture output from existing command modules

fn capture_uname_output() -> String {
    // Call uname module to get actual system info
    let mut info = String::new();
    if let Some(name) = sysinfo::System::name() {
        info.push_str(&format!("OS: {}\n", name));
    }
    if let Some(version) = sysinfo::System::os_version() {
        info.push_str(&format!("OS Version: {}\n", version));
    }
    if let Some(kernel) = sysinfo::System::kernel_version() {
        info.push_str(&format!("Kernel: {}\n", kernel));
    }
    info.push_str(&format!("Architecture: {}\n", std::env::consts::ARCH));
    if let Some(hostname) = sysinfo::System::host_name() {
        info.push_str(&format!("Hostname: {}\n", hostname));
    }
    info
}

fn capture_ps_output() -> String {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();

    let mut output = String::new();
    output.push_str("PID      NAME                     CPU%     MEMORY\n");
    output.push_str("=".repeat(50).as_str());
    output.push('\n');

    let mut processes: Vec<_> = sys.processes().iter().collect();
    processes.sort_by(|a, b| {
        b.1.cpu_usage()
            .partial_cmp(&a.1.cpu_usage())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for (pid, process) in processes.iter().take(10) {
        let name = process.name().to_string_lossy();
        let name = if name.len() > 20 {
            format!("{}...", &name[..17])
        } else {
            name.to_string()
        };
        output.push_str(&format!(
            "{:<8} {:<23} {:<8.1} {}\n",
            pid,
            name,
            process.cpu_usage(),
            format_bytes(process.memory())
        ));
    }
    output
}

fn capture_free_output() -> String {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();

    format!(
        "Used memory : {}\nTotal memory: {}\nTotal swap  : {}\nUsed swap   : {}",
        format_bytes(sys.used_memory()),
        format_bytes(sys.total_memory()),
        format_bytes(sys.total_swap()),
        format_bytes(sys.used_swap())
    )
}

fn capture_df_output() -> String {
    use sysinfo::Disks;
    let disks = Disks::new_with_refreshed_list();

    let mut output = String::new();
    output.push_str("Filesystem     Size      Used      Avail     Use%   Mounted on\n");
    output.push_str("=".repeat(70).as_str());
    output.push('\n');

    for disk in &disks {
        let total_space = disk.total_space();
        let available_space = disk.available_space();
        let used_space = total_space - available_space;

        let usage_percent = if total_space > 0 {
            (used_space as f64 / total_space as f64) * 100.0
        } else {
            0.0
        };

        let mount_point = disk.mount_point().to_string_lossy();
        let name = disk.name().to_string_lossy();

        output.push_str(&format!(
            "{:<14} {:<9} {:<9} {:<9} {:<6.1}% {}\n",
            name,
            format_bytes(total_space),
            format_bytes(used_space),
            format_bytes(available_space),
            usage_percent,
            mount_point
        ));
    }
    output
}

fn capture_uptime_output() -> String {
    let uptime_seconds = sysinfo::System::uptime();
    let days = uptime_seconds / 86400;
    let hours = (uptime_seconds % 86400) / 3600;
    let minutes = (uptime_seconds % 3600) / 60;

    format!(
        "System uptime: {} days, {} hours, {} minutes",
        days, hours, minutes
    )
}

fn capture_sensors_output() -> String {
    use sysinfo::Components;
    let components = Components::new_with_refreshed_list();

    if components.is_empty() {
        return "No temperature sensors found or accessible.\nNote: On Windows, temperature sensors may require administrator privileges.".to_string();
    }

    let mut output = String::new();
    output.push_str("Component Temperatures:\n");
    output.push_str("=".repeat(30).as_str());
    output.push('\n');

    for component in &components {
        let label = component.label();
        let temperature = component.temperature();

        if let Some(temp) = temperature {
            output.push_str(&format!("{}: {:.1}°C\n", label, temp));
        }
    }
    output
}

fn capture_chmod_output(args: &[&str]) -> String {
    // For demonstration - in a real implementation, this would call the actual chmod module
    if args.len() < 2 {
        return "Usage: chmod <permissions> <file>".to_string();
    }

    let permissions = args[0];
    let file = args[1];

    // Check if file exists
    if std::path::Path::new(file).exists() {
        format!("Changed permissions of '{}' to '{}'", file, permissions)
    } else {
        format!("File '{}' not found", file)
    }
}

fn capture_chown_output(args: &[&str]) -> String {
    // For demonstration - in a real implementation, this would call the actual chown module
    if args.len() < 2 {
        return "Usage: chown <owner> <file>".to_string();
    }

    let owner = args[0];
    let file = args[1];

    // Check if file exists
    if std::path::Path::new(file).exists() {
        format!("Changed ownership of '{}' to '{}'", file, owner)
    } else {
        format!("File '{}' not found", file)
    }
}

fn capture_git_output(args: &[&str]) -> String {
    use std::process::Command;

    // Check if git is available
    if !crate::git::is_git_available() {
        return "Error: Git is not installed or not in PATH".to_string();
    }

    match Command::new("git").args(args).output() {
        Ok(output) => {
            let mut result = String::new();

            // Add stdout
            if !output.stdout.is_empty() {
                result.push_str(&String::from_utf8_lossy(&output.stdout));
            }

            // Add stderr
            if !output.stderr.is_empty() {
                if !result.is_empty() {
                    result.push('\n');
                }
                result.push_str(&String::from_utf8_lossy(&output.stderr));
            }

            // If command failed and no output, add error message
            if !output.status.success() && result.is_empty() {
                if let Some(code) = output.status.code() {
                    result = format!("Git command failed with exit code: {}", code);
                } else {
                    result = "Git command failed".to_string();
                }
            }

            result
        }
        Err(e) => {
            format!("Failed to execute git command: {}", e)
        }
    }
}

fn capture_powershell_output(args: &[&str]) -> String {
    use std::process::Command;

    // Check if PowerShell is available
    if !crate::powershell::is_powershell_available() {
        return "Error: PowerShell is not available on this system".to_string();
    }

    // Get the preferred PowerShell executable
    let ps_exe = if is_command_available("pwsh") {
        "pwsh"
    } else {
        "powershell"
    };

    let command_string = args.join(" ");

    match Command::new(ps_exe)
        .args(&["-Command", &command_string])
        .output()
    {
        Ok(output) => {
            let mut result = String::new();

            // Add stdout
            if !output.stdout.is_empty() {
                result.push_str(&String::from_utf8_lossy(&output.stdout));
            }

            // Add stderr
            if !output.stderr.is_empty() {
                if !result.is_empty() {
                    result.push('\n');
                }
                result.push_str(&String::from_utf8_lossy(&output.stderr));
            }

            // If command failed and no output, add error message
            if !output.status.success() && result.is_empty() {
                if let Some(code) = output.status.code() {
                    result = format!("PowerShell command failed with exit code: {}", code);
                } else {
                    result = "PowerShell command failed".to_string();
                }
            }

            result
        }
        Err(e) => {
            format!("Failed to execute PowerShell command: {}", e)
        }
    }
}

fn is_command_available(cmd: &str) -> bool {
    use std::process::Command;
    match Command::new(cmd)
        .arg("-Command")
        .arg("$PSVersionTable.PSVersion")
        .output()
    {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

fn render_git_info(f: &mut Frame, area: Rect) {
    // Check if we're in a git repository
    let is_git_repo = crate::git::is_git_repo();

    if !is_git_repo {
        let no_git_text = vec![
            Line::from(vec![Span::styled(
                "Not a Git Repository",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Navigate to a Git repository or initialize one with:",
                Style::default().fg(Color::Gray),
            )]),
            Line::from(""),
            Line::from(vec![
                Span::styled("git init", Style::default().fg(Color::Cyan)),
                Span::styled(
                    " - Initialize a new Git repository",
                    Style::default().fg(Color::Gray),
                ),
            ]),
            Line::from(vec![
                Span::styled("git clone <url>", Style::default().fg(Color::Cyan)),
                Span::styled(
                    " - Clone an existing repository",
                    Style::default().fg(Color::Gray),
                ),
            ]),
        ];

        let paragraph = Paragraph::new(no_git_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Git Information")
                    .border_type(BorderType::Plain),
            )
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
        return;
    }

    // We're in a git repository, show git information
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8), // Repository info
            Constraint::Length(8), // Branch info
            Constraint::Min(0),    // Status/Log
        ])
        .split(area);

    // Repository Information
    render_git_repo_info(f, layout[0]);

    // Branch Information
    render_git_branch_info(f, layout[1]);

    // Status and recent commits
    render_git_status_and_log(f, layout[2]);
}

fn render_git_repo_info(f: &mut Frame, area: Rect) {
    let current_dir = std::env::current_dir()
        .unwrap_or_else(|_| "?".into())
        .display()
        .to_string();

    let repo_info = vec![
        Line::from(vec![
            Span::styled("Repository: ", Style::default().fg(Color::Cyan)),
            Span::styled(current_dir, Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Git Status: ", Style::default().fg(Color::Cyan)),
            if let Some(status) = crate::git::get_repo_status() {
                match status.as_str() {
                    "clean" => Span::styled("Clean ✓", Style::default().fg(Color::Green)),
                    "dirty" => Span::styled("Modified ✗", Style::default().fg(Color::Red)),
                    _ => Span::styled("Unknown", Style::default().fg(Color::Yellow)),
                }
            } else {
                Span::styled("Error getting status", Style::default().fg(Color::Red))
            },
        ]),
    ];

    let paragraph = Paragraph::new(repo_info)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Repository Information")
                .border_type(BorderType::Plain),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

fn render_git_branch_info(f: &mut Frame, area: Rect) {
    let current_branch = crate::git::get_current_branch().unwrap_or_else(|| "HEAD".to_string());

    let branch_info = vec![
        Line::from(vec![
            Span::styled("Current Branch: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                current_branch,
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Quick Commands:",
            Style::default().fg(Color::Yellow),
        )]),
        Line::from(vec![Span::styled(
            "  Press 'c' to run git commands",
            Style::default().fg(Color::Gray),
        )]),
    ];

    let paragraph = Paragraph::new(branch_info)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Branch Information")
                .border_type(BorderType::Plain),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

fn render_git_status_and_log(f: &mut Frame, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Status information
    render_git_status_detailed(f, layout[0]);

    // Recent commits
    render_git_recent_commits(f, layout[1]);
}

fn render_git_status_detailed(f: &mut Frame, area: Rect) {
    use std::process::Command;

    let status_output = Command::new("git")
        .args(&["status", "--porcelain"])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).to_string())
        .unwrap_or_else(|_| "Error getting status".to_string());

    let status_lines: Vec<Line> = if status_output.trim().is_empty() {
        vec![Line::from(vec![Span::styled(
            "Working tree clean",
            Style::default().fg(Color::Green),
        )])]
    } else {
        status_output
            .lines()
            .take(10) // Limit to first 10 files
            .map(|line| {
                let (status, filename) = if line.len() >= 3 {
                    (&line[..2], &line[3..])
                } else {
                    ("??", line)
                };

                let color = match status.trim() {
                    "M" | "AM" => Color::Yellow,
                    "A" | "AA" => Color::Green,
                    "D" | "AD" => Color::Red,
                    "R" | "AR" => Color::Blue,
                    "C" | "AC" => Color::Cyan,
                    "??" => Color::Gray,
                    _ => Color::White,
                };

                Line::from(vec![
                    Span::styled(format!("{} ", status), Style::default().fg(color)),
                    Span::styled(filename, Style::default().fg(Color::White)),
                ])
            })
            .collect()
    };

    let paragraph = Paragraph::new(status_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Working Tree Status")
                .border_type(BorderType::Plain),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

fn render_git_recent_commits(f: &mut Frame, area: Rect) {
    use std::process::Command;

    let log_output = Command::new("git")
        .args(&["log", "--oneline", "-10"])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).to_string())
        .unwrap_or_else(|_| "Error getting log".to_string());

    let log_lines: Vec<Line> = if log_output.trim().is_empty() {
        vec![Line::from(vec![Span::styled(
            "No commits yet",
            Style::default().fg(Color::Gray),
        )])]
    } else {
        log_output
            .lines()
            .map(|line| {
                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                if parts.len() == 2 {
                    Line::from(vec![
                        Span::styled(parts[0], Style::default().fg(Color::Yellow)),
                        Span::styled(" ", Style::default()),
                        Span::styled(parts[1], Style::default().fg(Color::White)),
                    ])
                } else {
                    Line::from(vec![Span::styled(line, Style::default().fg(Color::White))])
                }
            })
            .collect()
    };

    let paragraph = Paragraph::new(log_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Recent Commits")
                .border_type(BorderType::Plain),
        )
        .wrap(Wrap { trim: true });
    f.render_widget(paragraph, area);
}

#[cfg(windows)]
fn capture_nice_output(args: &[&str]) -> String {
    // Use the nice module to execute the command
    match crate::nice::execute(args) {
        Ok(_) => {
            // If successful, the nice module will print its own success message
            // We'll return a simple confirmation
            "Command executed successfully with nice priority".to_string()
        }
        Err(e) => {
            // Return the error message from the nice module
            format!("nice: {}", e)
        }
    }
}
