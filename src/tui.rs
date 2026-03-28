use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, BorderType, Borders, Cell, Clear, Gauge, List, ListItem, ListState, Paragraph, Row,
        Table, Wrap,
    },
};
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::{env, nproc};

const TAB_TITLES: [&str; 7] = [
    "System",
    "Processes",
    "Memory",
    "Disks",
    "Sensors",
    "Files",
    "Git",
];

const OUTPUT_LIMIT: usize = 500;

#[derive(Debug, Clone)]
struct FileItem {
    name: String,
    path: PathBuf,
    is_dir: bool,
    size: u64,
}

#[derive(Debug)]
pub struct App {
    selected_tab: usize,
    should_quit: bool,
    show_help: bool,
    show_command_palette: bool,
    current_dir: String,
    files: Vec<FileItem>,
    file_state: ListState,
    command_input: String,
    command_output: Vec<String>,
    command_history: Vec<String>,
    history_cursor: Option<usize>,
    status_line: String,
    last_refresh: Instant,
}

impl Default for App {
    fn default() -> Self {
        let mut app = Self {
            selected_tab: 0,
            should_quit: false,
            show_help: false,
            show_command_palette: false,
            current_dir: std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .display()
                .to_string(),
            files: Vec::new(),
            file_state: ListState::default(),
            command_input: String::new(),
            command_output: Vec::new(),
            command_history: Vec::new(),
            history_cursor: None,
            status_line: "Ready".to_string(),
            last_refresh: Instant::now(),
        };
        app.refresh_files();
        app
    }
}

impl App {
    fn refresh_files(&mut self) {
        self.files.clear();

        let dir = PathBuf::from(&self.current_dir);
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();

                if let Ok(metadata) = entry.metadata() {
                    self.files.push(FileItem {
                        name,
                        path,
                        is_dir: metadata.is_dir(),
                        size: if metadata.is_file() {
                            metadata.len()
                        } else {
                            0
                        },
                    });
                }
            }

            self.files.sort_by(|a, b| {
                b.is_dir
                    .cmp(&a.is_dir)
                    .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
            });

            if self.files.is_empty() {
                self.file_state.select(None);
            } else if self.file_state.selected().is_none() {
                self.file_state.select(Some(0));
            } else if let Some(selected) = self.file_state.selected() {
                if selected >= self.files.len() {
                    self.file_state.select(Some(self.files.len() - 1));
                }
            }

            self.status_line = format!("Loaded {} entries", self.files.len());
        } else {
            self.status_line = format!("Cannot read directory {}", self.current_dir);
        }

        self.last_refresh = Instant::now();
    }

    fn next_tab(&mut self) {
        self.selected_tab = (self.selected_tab + 1) % TAB_TITLES.len();
    }

    fn previous_tab(&mut self) {
        if self.selected_tab == 0 {
            self.selected_tab = TAB_TITLES.len() - 1;
        } else {
            self.selected_tab -= 1;
        }
    }

    fn select_tab_index(&mut self, index: usize) {
        if index < TAB_TITLES.len() {
            self.selected_tab = index;
        }
    }

    fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }

    fn toggle_command_palette(&mut self) {
        self.show_command_palette = !self.show_command_palette;
        if !self.show_command_palette {
            self.history_cursor = None;
            self.command_input.clear();
        }
    }

    fn push_output_line(&mut self, line: String) {
        self.command_output.push(line);
        if self.command_output.len() > OUTPUT_LIMIT {
            let trim = self.command_output.len() - OUTPUT_LIMIT;
            self.command_output.drain(0..trim);
        }
    }

    fn append_output_text(&mut self, text: &str) {
        if text.trim().is_empty() {
            self.push_output_line("(no output)".to_string());
            return;
        }

        for line in text.lines() {
            self.push_output_line(line.to_string());
        }
    }

    fn file_next(&mut self) {
        if self.files.is_empty() {
            return;
        }

        let index = self.file_state.selected().unwrap_or(0);
        let next = (index + 1).min(self.files.len() - 1);
        self.file_state.select(Some(next));
    }

    fn file_previous(&mut self) {
        if self.files.is_empty() {
            return;
        }

        let index = self.file_state.selected().unwrap_or(0);
        let prev = index.saturating_sub(1);
        self.file_state.select(Some(prev));
    }

    fn open_selected_item(&mut self) {
        let Some(index) = self.file_state.selected() else {
            return;
        };
        if index >= self.files.len() {
            return;
        }

        let selected = self.files[index].clone();
        if selected.is_dir {
            self.current_dir = selected.path.display().to_string();
            self.refresh_files();
            self.status_line = format!("Entered {}", selected.path.display());
        } else {
            self.push_output_line(format!(
                "Selected file: {} ({} bytes)",
                selected.path.display(),
                selected.size
            ));
            self.status_line = format!("Selected file {}", selected.name);
        }
    }

    fn run_input_command(&mut self) {
        if self.command_input.trim().is_empty() {
            return;
        }

        let line = self.command_input.trim().to_string();
        self.status_line = format!("Running: {}", line);

        if self
            .command_history
            .last()
            .map(|last| last != &line)
            .unwrap_or(true)
        {
            self.command_history.push(line.clone());
        }

        self.push_output_line(format!("> {}", line));

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            self.command_input.clear();
            self.history_cursor = None;
            return;
        }

        let command = parts[0].to_lowercase();

        match command.as_str() {
            "cd" => {
                if parts.len() < 2 {
                    self.push_output_line("Usage: cd <directory>".to_string());
                } else if let Err(err) = std::env::set_current_dir(parts[1]) {
                    self.push_output_line(format!("cd: {}", err));
                } else {
                    self.current_dir = std::env::current_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .display()
                        .to_string();
                    self.refresh_files();
                    self.push_output_line(format!("Changed directory to {}", self.current_dir));
                }
            }
            "pwd" => self.push_output_line(self.current_dir.clone()),
            "ls" => {
                if self.files.is_empty() {
                    self.push_output_line("(empty directory)".to_string());
                } else {
                    let lines: Vec<String> = self
                        .files
                        .iter()
                        .map(|item| {
                            let kind = if item.is_dir { "[DIR]" } else { "[FIL]" };
                            format!("{} {}", kind, item.name)
                        })
                        .collect();
                    for line in lines {
                        self.push_output_line(line);
                    }
                }
            }
            "clear" => {
                self.command_output.clear();
                self.push_output_line("Output cleared".to_string());
            }
            "help" => {
                self.push_output_line("Built-in commands:".to_string());
                self.push_output_line("cd pwd ls uname ps free df uptime sensors".to_string());
                self.push_output_line("git psh env nproc set unset clear help".to_string());
                self.push_output_line(
                    "Other commands are executed in Winix first, then PowerShell fallback"
                        .to_string(),
                );
            }
            "uname" => self.append_output_text(&capture_uname_output()),
            "ps" => self.append_output_text(&capture_ps_output()),
            "free" => self.append_output_text(&capture_free_output()),
            "df" => self.append_output_text(&capture_df_output()),
            "uptime" => self.append_output_text(&capture_uptime_output()),
            "sensors" => self.append_output_text(&capture_sensors_output()),
            "git" => {
                if parts.len() < 2 {
                    self.push_output_line("Usage: git <subcommand> [options]".to_string());
                } else {
                    self.append_output_text(&capture_git_output(&parts[1..]));
                }
            }
            "psh" | "powershell" => {
                if parts.len() < 2 {
                    self.push_output_line("Usage: psh <command>".to_string());
                } else {
                    self.append_output_text(&capture_powershell_output(&parts[1..]));
                }
            }
            "env" => {
                let args = parts[1..]
                    .iter()
                    .map(|arg| arg.to_string())
                    .collect::<Vec<_>>();
                self.append_output_text(&capture_env_output(&args));
            }
            "nproc" => {
                let args = parts[1..]
                    .iter()
                    .map(|arg| arg.to_string())
                    .collect::<Vec<_>>();
                self.append_output_text(&capture_nproc_output(&args));
            }
            "set" => {
                if parts.len() < 2 {
                    self.push_output_line("Usage: set VAR=VALUE".to_string());
                } else {
                    let var_assignment = parts[1..].join(" ");
                    let var_parts: Vec<&str> = var_assignment.splitn(2, '=').collect();
                    if var_parts.len() != 2 {
                        self.push_output_line("Usage: set VAR=VALUE".to_string());
                    } else {
                        let name = var_parts[0].trim();
                        let value = var_parts[1];
                        match env::set_env_var(name, value) {
                            Ok(_) => self.push_output_line(format!("Set {}={}", name, value)),
                            Err(err) => self.push_output_line(format!("set: {}", err)),
                        }
                    }
                }
            }
            "unset" => {
                if parts.len() < 2 {
                    self.push_output_line("Usage: unset VAR".to_string());
                } else {
                    let name = parts[1];
                    match env::remove_env_var(name) {
                        Ok(_) => self.push_output_line(format!("Unset {}", name)),
                        Err(err) => self.push_output_line(format!("unset: {}", err)),
                    }
                }
            }
            _ => {
                let (ok, output) = capture_winix_command_output(&line);
                if ok {
                    if output.trim().is_empty() {
                        self.push_output_line("Done".to_string());
                    } else {
                        self.append_output_text(&output);
                    }
                    self.refresh_files();
                } else if output.to_lowercase().contains("unknown command") {
                    self.append_output_text(&capture_powershell_output(&parts));
                } else {
                    self.append_output_text(&output);
                }
            }
        }

        self.command_input.clear();
        self.history_cursor = None;
    }

    fn history_up(&mut self) {
        if self.command_history.is_empty() {
            return;
        }

        let next = match self.history_cursor {
            None => self.command_history.len().saturating_sub(1),
            Some(0) => 0,
            Some(value) => value.saturating_sub(1),
        };

        self.history_cursor = Some(next);
        self.command_input = self.command_history[next].clone();
    }

    fn history_down(&mut self) {
        if self.command_history.is_empty() {
            return;
        }

        let Some(current) = self.history_cursor else {
            return;
        };

        if current + 1 >= self.command_history.len() {
            self.history_cursor = None;
            self.command_input.clear();
        } else {
            let next = current + 1;
            self.history_cursor = Some(next);
            self.command_input = self.command_history[next].clone();
        }
    }
}

pub fn run_tui() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::default();
    let result = run_app(&mut terminal, &mut app);

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
        terminal.draw(|frame| draw_ui(frame, app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                if app.show_command_palette {
                    match key.code {
                        KeyCode::Esc => app.toggle_command_palette(),
                        KeyCode::Enter => app.run_input_command(),
                        KeyCode::Backspace => {
                            app.command_input.pop();
                        }
                        KeyCode::Up => app.history_up(),
                        KeyCode::Down => app.history_down(),
                        KeyCode::Char(c) => app.command_input.push(c),
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => app.should_quit = true,
                        KeyCode::Char('?') | KeyCode::Char('h') | KeyCode::Char('H') => {
                            app.toggle_help()
                        }
                        KeyCode::Char(':') | KeyCode::Char('c') | KeyCode::Char('C') => {
                            app.toggle_command_palette()
                        }
                        KeyCode::Tab | KeyCode::Right => app.next_tab(),
                        KeyCode::BackTab | KeyCode::Left => app.previous_tab(),
                        KeyCode::Char('1') => app.select_tab_index(0),
                        KeyCode::Char('2') => app.select_tab_index(1),
                        KeyCode::Char('3') => app.select_tab_index(2),
                        KeyCode::Char('4') => app.select_tab_index(3),
                        KeyCode::Char('5') => app.select_tab_index(4),
                        KeyCode::Char('6') => app.select_tab_index(5),
                        KeyCode::Char('7') => app.select_tab_index(6),
                        KeyCode::Char('r') | KeyCode::Char('R') => {
                            app.refresh_files();
                            app.status_line = "Refreshed view".to_string();
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if app.selected_tab == 5 {
                                app.file_next();
                            }
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if app.selected_tab == 5 {
                                app.file_previous();
                            }
                        }
                        KeyCode::Enter => {
                            if app.selected_tab == 5 {
                                app.open_selected_item();
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        if app.should_quit {
            break;
        }

        if app.last_refresh.elapsed() >= Duration::from_secs(2) {
            app.last_refresh = Instant::now();
        }
    }

    Ok(())
}

fn draw_ui(frame: &mut Frame, app: &mut App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Min(0),
            Constraint::Length(2),
        ])
        .split(frame.area());

    render_header(frame, root[0], app);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(26), Constraint::Min(0)])
        .split(root[1]);

    render_sidebar(frame, body[0], app);

    let content = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(8)])
        .split(body[1]);

    render_active_tab(frame, content[0], app);
    render_output_panel(frame, content[1], app);
    render_footer(frame, root[2], app);

    if app.show_help {
        render_help_modal(frame);
    }

    if app.show_command_palette {
        render_command_palette(frame, app);
    }
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let lines = vec![
        Line::from(Span::styled(
            " __      __ ___ _   _ ___ __  __",
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            " \\ \\ /\\ / /|_ _| \\ | |_ _|  \\/  |",
            Style::default().fg(Color::Cyan),
        )),
        Line::from(Span::styled(
            "  \\ V  V /  | ||  \\| || || |\\/| |",
            Style::default().fg(Color::Cyan),
        )),
        Line::from(Span::styled(
            "   \\_/\\_/  |___|_|\\_|___|_|  |_|",
            Style::default().fg(Color::Cyan),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("Modern Command Center", Style::default().fg(Color::White)),
            Span::styled("  |  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("Workspace: {}", app.current_dir),
                Style::default().fg(Color::Gray),
            ),
        ]),
    ];

    let header = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Winix TUI ")
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(header, area);
}

fn render_sidebar(frame: &mut Frame, area: Rect, app: &App) {
    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(12), Constraint::Min(0)])
        .split(area);

    let items = TAB_TITLES
        .iter()
        .enumerate()
        .map(|(i, name)| ListItem::new(format!("{}  {}", i + 1, name)))
        .collect::<Vec<_>>();

    let nav = List::new(items)
        .block(
            Block::default()
                .title(" Views ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .style(Style::default().fg(Color::Gray))
        .highlight_symbol("> ")
        .highlight_style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        );

    let mut nav_state = ListState::default();
    nav_state.select(Some(app.selected_tab));
    frame.render_stateful_widget(nav, split[0], &mut nav_state);

    let status_lines = vec![
        Line::from(vec![
            Span::styled("Status: ", Style::default().fg(Color::LightBlue)),
            Span::styled(&app.status_line, Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Shortcuts",
            Style::default().fg(Color::Yellow),
        )),
        Line::from("Tab/Shift+Tab  switch view"),
        Line::from("1..7           jump view"),
        Line::from(":             command palette"),
        Line::from("j/k or up/down file nav"),
        Line::from("enter          open folder"),
        Line::from("r              refresh"),
        Line::from("?              help"),
        Line::from("q              quit"),
    ];

    let status = Paragraph::new(status_lines)
        .block(
            Block::default()
                .title(" Operations ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(status, split[1]);
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    let text = Line::from(vec![
        Span::styled("View", Style::default().fg(Color::LightBlue)),
        Span::raw(format!(" {} ", TAB_TITLES[app.selected_tab])),
        Span::styled("|", Style::default().fg(Color::DarkGray)),
        Span::styled(
            " Press ':' for command palette ",
            Style::default().fg(Color::White),
        ),
        Span::styled("|", Style::default().fg(Color::DarkGray)),
        Span::styled(" Press '?' for help ", Style::default().fg(Color::White)),
    ]);

    let footer = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::Blue)),
    );

    frame.render_widget(footer, area);
}

fn render_output_panel(frame: &mut Frame, area: Rect, app: &App) {
    let start = app.command_output.len().saturating_sub(10);
    let lines = app.command_output[start..]
        .iter()
        .map(|line| Line::from(line.as_str()))
        .collect::<Vec<_>>();

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Command Output ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(panel, area);
}

fn render_active_tab(frame: &mut Frame, area: Rect, app: &mut App) {
    match app.selected_tab {
        0 => render_system_tab(frame, area),
        1 => render_process_tab(frame, area),
        2 => render_memory_tab(frame, area),
        3 => render_disks_tab(frame, area),
        4 => render_sensors_tab(frame, area),
        5 => render_files_tab(frame, area, app),
        6 => render_git_tab(frame, area),
        _ => {}
    }
}

fn render_system_tab(frame: &mut Frame, area: Rect) {
    let split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    let left = Paragraph::new(get_system_info())
        .block(
            Block::default()
                .title(" System Snapshot ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(left, split[0]);

    let cpu_block = Paragraph::new(cpu_lanes_text())
        .block(
            Block::default()
                .title(" CPU Lanes ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(cpu_block, split[1]);
}

fn render_process_tab(frame: &mut Frame, area: Rect) {
    let header = Row::new(vec!["PID", "NAME", "CPU", "MEMORY"]).style(
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    );

    let rows = get_process_list()
        .into_iter()
        .enumerate()
        .map(|(idx, row)| {
            let style = if idx % 2 == 0 {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::Gray)
            };
            Row::new(vec![
                Cell::from(row.0),
                Cell::from(row.1),
                Cell::from(row.2),
                Cell::from(row.3),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Percentage(50),
            Constraint::Length(10),
            Constraint::Length(14),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(" Top Processes ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );

    frame.render_widget(table, area);
}

fn render_memory_tab(frame: &mut Frame, area: Rect) {
    let memory = get_memory_info();

    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(0),
        ])
        .split(area);

    let memory_gauge = Gauge::default()
        .block(
            Block::default()
                .title(" RAM ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .gauge_style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        )
        .ratio(memory.usage_ratio)
        .label(format!("{:.1}%", memory.usage_ratio * 100.0));

    frame.render_widget(memory_gauge, split[0]);

    let swap_gauge = Gauge::default()
        .block(
            Block::default()
                .title(" SWAP ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .gauge_style(Style::default().fg(Color::Yellow))
        .ratio(memory.swap_ratio)
        .label(format!("{:.1}%", memory.swap_ratio * 100.0));

    frame.render_widget(swap_gauge, split[1]);

    let details = Paragraph::new(memory.details)
        .block(
            Block::default()
                .title(" Memory Details ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(details, split[2]);
}

fn render_disks_tab(frame: &mut Frame, area: Rect) {
    let disks = get_disk_rows();

    let header = Row::new(vec!["NAME", "SIZE", "USED", "AVAIL", "USE%", "MOUNT"]).style(
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD),
    );

    let rows = disks
        .into_iter()
        .map(|d| {
            Row::new(vec![
                Cell::from(d.name),
                Cell::from(d.size),
                Cell::from(d.used),
                Cell::from(d.avail),
                Cell::from(d.use_percent),
                Cell::from(d.mount),
            ])
        })
        .collect::<Vec<_>>();

    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(8),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(" Disk Utilization ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );

    frame.render_widget(table, area);
}

fn render_sensors_tab(frame: &mut Frame, area: Rect) {
    let paragraph = Paragraph::new(get_sensor_info())
        .block(
            Block::default()
                .title(" Sensors ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(paragraph, area);
}

fn render_files_tab(frame: &mut Frame, area: Rect, app: &mut App) {
    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(6),
        ])
        .split(area);

    let header = Paragraph::new(format!("Path: {}", app.current_dir)).block(
        Block::default()
            .title(" File Browser ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );

    frame.render_widget(header, split[0]);

    let items = app
        .files
        .iter()
        .map(|item| {
            let kind = if item.is_dir { "[DIR]" } else { "[FIL]" };
            ListItem::new(format!("{} {}", kind, item.name))
        })
        .collect::<Vec<_>>();

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Entries ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .highlight_symbol("> ")
        .highlight_style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_stateful_widget(list, split[1], &mut app.file_state);

    let details = selected_file_details(app);
    let details_block = Paragraph::new(details)
        .block(
            Block::default()
                .title(" Selected Entry ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(details_block, split[2]);
}

fn render_git_tab(frame: &mut Frame, area: Rect) {
    if !crate::git::is_git_repo() {
        let text = Text::from(vec![
            Line::from("Not in a Git repository"),
            Line::from(""),
            Line::from("Move to a repository or run: git init"),
            Line::from("Use command palette (:) for git commands."),
        ]);

        let block = Paragraph::new(text)
            .block(
                Block::default()
                    .title(" Git ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Blue)),
            )
            .wrap(Wrap { trim: true });

        frame.render_widget(block, area);
        return;
    }

    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(5), Constraint::Min(0)])
        .split(area);

    let repo_text = vec![
        Line::from(vec![
            Span::styled("Branch: ", Style::default().fg(Color::LightBlue)),
            Span::styled(
                crate::git::get_current_branch().unwrap_or_else(|| "HEAD".to_string()),
                Style::default().fg(Color::LightMagenta),
            ),
        ]),
        Line::from(vec![
            Span::styled("Status: ", Style::default().fg(Color::LightBlue)),
            Span::styled(
                crate::git::get_repo_status().unwrap_or_else(|| "unknown".to_string()),
                Style::default().fg(Color::White),
            ),
        ]),
    ];

    let repo_block = Paragraph::new(repo_text).block(
        Block::default()
            .title(" Repository Summary ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Blue)),
    );

    frame.render_widget(repo_block, split[0]);

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(split[1]);

    let status = Paragraph::new(git_status_text())
        .block(
            Block::default()
                .title(" Working Tree ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(status, columns[0]);

    let log = Paragraph::new(git_log_text())
        .block(
            Block::default()
                .title(" Recent Commits ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(log, columns[1]);
}

fn render_help_modal(frame: &mut Frame) {
    let area = centered_rect(72, 72, frame.area());
    frame.render_widget(Clear, area);

    let lines = vec![
        Line::from(Span::styled(
            "Winix TUI Help",
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("Global"),
        Line::from("  q            quit"),
        Line::from("  ? or h       toggle help"),
        Line::from("  :            command palette"),
        Line::from("  tab/shift+tab next/prev view"),
        Line::from("  1..7         jump directly to view"),
        Line::from("  r            refresh files/status"),
        Line::from(""),
        Line::from("Files view"),
        Line::from("  j/k or arrows move selection"),
        Line::from("  enter         open directory or inspect file"),
        Line::from(""),
        Line::from("Command palette"),
        Line::from("  enter         execute"),
        Line::from("  up/down       history"),
        Line::from("  esc           close"),
        Line::from(""),
        Line::from("Press ? to close this window."),
    ];

    let widget = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Help ")
                .borders(Borders::ALL)
                .border_type(BorderType::Thick)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(widget, area);
}

fn render_command_palette(frame: &mut Frame, app: &App) {
    let area = centered_rect(85, 75, frame.area());
    frame.render_widget(Clear, area);

    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    let input = Paragraph::new(app.command_input.as_str())
        .block(
            Block::default()
                .title(" Command Palette  (enter run, esc close) ")
                .borders(Borders::ALL)
                .border_type(BorderType::Thick)
                .border_style(Style::default().fg(Color::LightCyan)),
        )
        .style(
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        );

    frame.render_widget(input, split[0]);

    let start = app.command_output.len().saturating_sub(20);
    let output_lines = app.command_output[start..]
        .iter()
        .map(|line| Line::from(line.as_str()))
        .collect::<Vec<_>>();

    let output = Paragraph::new(output_lines)
        .block(
            Block::default()
                .title(" Output ")
                .borders(Borders::ALL)
                .border_type(BorderType::Plain)
                .border_style(Style::default().fg(Color::Blue)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(output, split[1]);
}

fn centered_rect(percent_x: u16, percent_y: u16, bounds: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(bounds);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn selected_file_details(app: &App) -> Text<'static> {
    let Some(index) = app.file_state.selected() else {
        return Text::from("No entry selected");
    };

    let Some(item) = app.files.get(index) else {
        return Text::from("No entry selected");
    };

    let kind = if item.is_dir { "Directory" } else { "File" };

    Text::from(vec![
        Line::from(format!("Name: {}", item.name)),
        Line::from(format!("Type: {}", kind)),
        Line::from(format!("Size: {}", format_bytes(item.size))),
        Line::from(format!("Path: {}", item.path.display())),
    ])
}

fn cpu_lanes_text() -> Text<'static> {
    use sysinfo::System;

    let mut system = System::new_all();
    system.refresh_all();

    let mut lines = Vec::new();
    for (idx, cpu) in system.cpus().iter().take(8).enumerate() {
        let usage = cpu.cpu_usage().clamp(0.0, 100.0);
        let filled = (usage / 5.0).round() as usize;
        let bar = format!(
            "{}{}",
            "#".repeat(filled),
            "-".repeat(20usize.saturating_sub(filled))
        );
        lines.push(Line::from(format!(
            "CPU {:02}: [{}] {:>5.1}%",
            idx, bar, usage
        )));
    }

    if lines.is_empty() {
        lines.push(Line::from("CPU data unavailable"));
    }

    Text::from(lines)
}

fn get_system_info() -> Text<'static> {
    let mut lines = Vec::new();

    if let Some(name) = sysinfo::System::name() {
        lines.push(Line::from(format!("OS: {}", name)));
    }
    if let Some(version) = sysinfo::System::os_version() {
        lines.push(Line::from(format!("Version: {}", version)));
    }
    if let Some(kernel) = sysinfo::System::kernel_version() {
        lines.push(Line::from(format!("Kernel: {}", kernel)));
    }
    if let Some(host) = sysinfo::System::host_name() {
        lines.push(Line::from(format!("Host: {}", host)));
    }

    lines.push(Line::from(format!("Arch: {}", std::env::consts::ARCH)));

    let uptime_seconds = sysinfo::System::uptime();
    let days = uptime_seconds / 86_400;
    let hours = (uptime_seconds % 86_400) / 3_600;
    let minutes = (uptime_seconds % 3_600) / 60;
    lines.push(Line::from(format!(
        "Uptime: {}d {}h {}m",
        days, hours, minutes
    )));

    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();
    lines.push(Line::from(format!("CPUs: {}", sys.cpus().len())));

    Text::from(lines)
}

fn get_process_list() -> Vec<(String, String, String, String)> {
    use sysinfo::System;

    let mut system = System::new_all();
    system.refresh_all();

    let mut rows = system.processes().iter().collect::<Vec<_>>();
    rows.sort_by(|a, b| {
        b.1.cpu_usage()
            .partial_cmp(&a.1.cpu_usage())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    rows.into_iter()
        .take(15)
        .map(|(pid, process)| {
            let mut name = process.name().to_string_lossy().to_string();
            if name.len() > 28 {
                name.truncate(25);
                name.push_str("...");
            }

            (
                pid.to_string(),
                name,
                format!("{:.1}%", process.cpu_usage()),
                format_bytes(process.memory()),
            )
        })
        .collect()
}

struct MemoryInfo {
    usage_ratio: f64,
    swap_ratio: f64,
    details: Text<'static>,
}

fn get_memory_info() -> MemoryInfo {
    use sysinfo::System;

    let mut system = System::new_all();
    system.refresh_all();

    let total_memory = system.total_memory();
    let used_memory = system.used_memory();
    let total_swap = system.total_swap();
    let used_swap = system.used_swap();

    let usage_ratio = if total_memory == 0 {
        0.0
    } else {
        used_memory as f64 / total_memory as f64
    };

    let swap_ratio = if total_swap == 0 {
        0.0
    } else {
        used_swap as f64 / total_swap as f64
    };

    let details = Text::from(vec![
        Line::from(format!("Used RAM : {}", format_bytes(used_memory))),
        Line::from(format!("Total RAM: {}", format_bytes(total_memory))),
        Line::from(format!(
            "Free RAM : {}",
            format_bytes(total_memory.saturating_sub(used_memory))
        )),
        Line::from(format!("Used Swap: {}", format_bytes(used_swap))),
        Line::from(format!("Total Swap: {}", format_bytes(total_swap))),
    ]);

    MemoryInfo {
        usage_ratio,
        swap_ratio,
        details,
    }
}

struct DiskRow {
    name: String,
    size: String,
    used: String,
    avail: String,
    use_percent: String,
    mount: String,
}

fn get_disk_rows() -> Vec<DiskRow> {
    use sysinfo::Disks;

    let disks = Disks::new_with_refreshed_list();
    disks
        .iter()
        .map(|disk| {
            let total = disk.total_space();
            let avail = disk.available_space();
            let used = total.saturating_sub(avail);
            let percent = if total == 0 {
                0.0
            } else {
                (used as f64 / total as f64) * 100.0
            };

            DiskRow {
                name: disk.name().to_string_lossy().to_string(),
                size: format_bytes(total),
                used: format_bytes(used),
                avail: format_bytes(avail),
                use_percent: format!("{:.1}%", percent),
                mount: disk.mount_point().to_string_lossy().to_string(),
            }
        })
        .collect()
}

fn get_sensor_info() -> Text<'static> {
    use sysinfo::Components;

    let components = Components::new_with_refreshed_list();
    if components.is_empty() {
        return Text::from(vec![
            Line::from("No sensor data available"),
            Line::from("Windows may require elevated privileges"),
            Line::from("or vendor-specific drivers."),
        ]);
    }

    let mut lines = vec![Line::from("Component temperatures")];
    lines.push(Line::from("----------------------------------------"));

    for component in &components {
        if let Some(temp) = component.temperature() {
            let label = component.label();
            let max = component
                .max()
                .map(|value| format!(" max {:.1}C", value))
                .unwrap_or_default();

            lines.push(Line::from(format!("{}: {:.1}C{}", label, temp, max)));
        }
    }

    Text::from(lines)
}

fn git_status_text() -> Text<'static> {
    use std::process::Command;

    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|_| "Unable to run git status".to_string());

    if output.trim().is_empty() {
        return Text::from("Working tree clean");
    }

    let mut lines = output
        .lines()
        .take(18)
        .map(|line| Line::from(line.to_string()))
        .collect::<Vec<_>>();

    if output.lines().count() > 18 {
        lines.push(Line::from("..."));
    }

    Text::from(lines)
}

fn git_log_text() -> Text<'static> {
    use std::process::Command;

    let output = Command::new("git")
        .args(["log", "--oneline", "-15"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|_| "Unable to run git log".to_string());

    if output.trim().is_empty() {
        return Text::from("No commits found");
    }

    Text::from(
        output
            .lines()
            .map(|line| Line::from(line.to_string()))
            .collect::<Vec<_>>(),
    )
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

fn capture_uname_output() -> String {
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

    let mut system = System::new_all();
    system.refresh_all();

    let mut out = String::new();
    out.push_str("PID      NAME                     CPU%     MEMORY\n");
    out.push_str("==================================================\n");

    let mut rows = system.processes().iter().collect::<Vec<_>>();
    rows.sort_by(|a, b| {
        b.1.cpu_usage()
            .partial_cmp(&a.1.cpu_usage())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    for (pid, process) in rows.into_iter().take(12) {
        let mut name = process.name().to_string_lossy().to_string();
        if name.len() > 20 {
            name.truncate(17);
            name.push_str("...");
        }
        out.push_str(&format!(
            "{:<8} {:<23} {:<8.1} {}\n",
            pid,
            name,
            process.cpu_usage(),
            format_bytes(process.memory())
        ));
    }

    out
}

fn capture_free_output() -> String {
    use sysinfo::System;

    let mut system = System::new_all();
    system.refresh_all();

    format!(
        "Used memory : {}\nTotal memory: {}\nTotal swap  : {}\nUsed swap   : {}",
        format_bytes(system.used_memory()),
        format_bytes(system.total_memory()),
        format_bytes(system.total_swap()),
        format_bytes(system.used_swap())
    )
}

fn capture_df_output() -> String {
    let rows = get_disk_rows();
    let mut out = String::new();
    out.push_str("NAME           SIZE       USED       AVAIL      USE%      MOUNT\n");
    out.push_str("===============================================================\n");

    for row in rows {
        out.push_str(&format!(
            "{:<14} {:<10} {:<10} {:<10} {:<8} {}\n",
            row.name, row.size, row.used, row.avail, row.use_percent, row.mount
        ));
    }

    out
}

fn capture_uptime_output() -> String {
    let uptime_seconds = sysinfo::System::uptime();
    let days = uptime_seconds / 86_400;
    let hours = (uptime_seconds % 86_400) / 3_600;
    let minutes = (uptime_seconds % 3_600) / 60;

    format!(
        "System uptime: {} days, {} hours, {} minutes",
        days, hours, minutes
    )
}

fn capture_sensors_output() -> String {
    get_sensor_info()
        .lines
        .iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

fn capture_git_output(args: &[&str]) -> String {
    use std::process::Command;

    if !is_command_available("git") {
        return "Error: git is not installed or not in PATH".to_string();
    }

    match Command::new("git").args(args).output() {
        Ok(output) => {
            let mut result = String::new();

            if !output.stdout.is_empty() {
                result.push_str(&String::from_utf8_lossy(&output.stdout));
            }

            if !output.stderr.is_empty() {
                if !result.is_empty() {
                    result.push('\n');
                }
                result.push_str(&String::from_utf8_lossy(&output.stderr));
            }

            if !output.status.success() && result.is_empty() {
                if let Some(code) = output.status.code() {
                    result = format!("git command failed with exit code {}", code);
                } else {
                    result = "git command failed".to_string();
                }
            }

            result
        }
        Err(err) => format!("Failed to execute git: {}", err),
    }
}

fn capture_powershell_output(args: &[&str]) -> String {
    use std::process::Command;
    let command = args.join(" ");
    if command.trim().is_empty() {
        return "PowerShell: empty command".to_string();
    }

    // Try a sequence of known shell names because --version checks can fail on some builds.
    let candidates = ["pwsh", "pwsh.exe", "powershell", "powershell.exe"];
    let mut launch_errors = Vec::new();

    for shell in candidates {
        match Command::new(shell)
            .args(["-NoLogo", "-NoProfile", "-Command", &command])
            .output()
        {
            Ok(output) => {
                let mut result = String::new();

                if !output.stdout.is_empty() {
                    result.push_str(&String::from_utf8_lossy(&output.stdout));
                }

                if !output.stderr.is_empty() {
                    if !result.is_empty() {
                        result.push('\n');
                    }
                    result.push_str(&String::from_utf8_lossy(&output.stderr));
                }

                if !output.status.success() && result.is_empty() {
                    if let Some(code) = output.status.code() {
                        result = format!("PowerShell exited with code {}", code);
                    } else {
                        result = "PowerShell command failed".to_string();
                    }
                }

                return result;
            }
            Err(err) => {
                if err.kind() != std::io::ErrorKind::NotFound {
                    launch_errors.push(format!("{}: {}", shell, err));
                }
            }
        }
    }

    if launch_errors.is_empty() {
        "Error: PowerShell executable not found. Install PowerShell 7 (pwsh) or enable Windows PowerShell."
            .to_string()
    } else {
        format!(
            "Error: PowerShell launch failed. {}",
            launch_errors.join(" | ")
        )
    }
}

fn capture_winix_command_output(line: &str) -> (bool, String) {
    use std::process::Command;

    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            return (
                false,
                format!("Failed to resolve current executable: {}", err),
            );
        }
    };

    match Command::new(exe).args(["--run", line]).output() {
        Ok(output) => {
            let mut result = String::new();

            if !output.stdout.is_empty() {
                result.push_str(&String::from_utf8_lossy(&output.stdout));
            }

            if !output.stderr.is_empty() {
                if !result.is_empty() {
                    result.push('\n');
                }
                result.push_str(&String::from_utf8_lossy(&output.stderr));
            }

            (output.status.success(), result)
        }
        Err(err) => (false, format!("Failed to execute Winix command: {}", err)),
    }
}

fn capture_env_output(args: &[String]) -> String {
    if args.is_empty() {
        let mut out = String::new();
        let mut vars = std::env::vars().collect::<Vec<_>>();
        vars.sort_by(|a, b| a.0.cmp(&b.0));

        for (idx, (key, value)) in vars.into_iter().enumerate() {
            if idx >= 40 {
                out.push_str("... output truncated\n");
                break;
            }
            out.push_str(&format!("{}={}\n", key, value));
        }

        return out;
    }

    format!("env command args: {}", args.join(" "))
}

fn capture_nproc_output(args: &[String]) -> String {
    if args.contains(&"--all".to_string()) {
        nproc::get_total_cpus().to_string()
    } else {
        nproc::get_available_cpus().to_string()
    }
}

fn is_command_available(name: &str) -> bool {
    use std::process::Command;

    Command::new(name)
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}
