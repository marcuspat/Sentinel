use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table, Tabs,
    },
    Frame,
};

use sentinel_core::RiskTier;

use crate::app::{App, LogLevel, Session, StepStatus, Tab};

/// Entry point for rendering the entire TUI.
pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header bar
            Constraint::Length(3), // tab bar
            Constraint::Min(0),    // main content
            Constraint::Length(1), // status bar
        ])
        .split(frame.area());

    render_header(frame, chunks[0], app);
    render_tabs(frame, chunks[1], app);

    match app.current_tab {
        Tab::Goal => render_goal_tab(frame, chunks[2], app),
        Tab::Investigation => render_investigation_tab(frame, chunks[2], app),
        Tab::Plan => render_plan_tab(frame, chunks[2], app),
        Tab::Execution => render_execution_tab(frame, chunks[2], app),
        Tab::Audit => render_audit_tab(frame, chunks[2], app),
    }

    render_status_bar(frame, chunks[3], app);
}

fn render_header(frame: &mut Frame, area: Rect, app: &App) {
    let session_info = match &app.session {
        Some(s) => format!(
            " Sentinel  |  Host: {}  |  Phase: {:?}{}",
            s.host,
            s.phase,
            if s.dry_run { "  [DRY-RUN]" } else { "" }
        ),
        None => " Sentinel — Agentic System Administration".to_string(),
    };

    let paragraph = Paragraph::new(session_info).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(paragraph, area);
}

fn render_tabs(frame: &mut Frame, area: Rect, app: &App) {
    let tab_titles: Vec<Line> = Tab::ALL
        .iter()
        .map(|t| Line::from(t.title()))
        .collect();

    let selected = app.current_tab.index();

    let tabs = Tabs::new(tab_titles)
        .block(Block::default().borders(Borders::BOTTOM))
        .select(selected)
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .style(Style::default().fg(Color::White));

    frame.render_widget(tabs, area);
}

fn render_goal_tab(frame: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    // Input box.
    let display = if app.goal_input.is_empty() {
        "Type your goal here…".to_string()
    } else {
        app.goal_input.clone()
    };
    let input_style = if app.goal_input.is_empty() {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default().fg(Color::White)
    };

    let input = Paragraph::new(display)
        .style(input_style)
        .block(
            Block::default()
                .title("Operational Goal")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );
    frame.render_widget(input, chunks[0]);

    // Help text.
    let help = Paragraph::new(
        "Enter your high-level goal (e.g. 'Ensure nginx is running and serving traffic').\n\
         Press Enter to start the investigation.  Press Tab to navigate between views.",
    )
    .block(Block::default().title("Help").borders(Borders::ALL))
    .style(Style::default().fg(Color::Gray));
    frame.render_widget(help, chunks[1]);
}

fn render_investigation_tab(frame: &mut Frame, area: Rect, app: &App) {
    match &app.session {
        None => {
            let p = Paragraph::new(
                "No active session.\n\nGo to the Goal tab and enter a goal to start.",
            )
            .block(Block::default().title("Investigation").borders(Borders::ALL))
            .style(Style::default().fg(Color::DarkGray));
            frame.render_widget(p, area);
        }
        Some(session) => {
            let items: Vec<ListItem> = session
                .log_entries
                .iter()
                .map(|e| {
                    let level_style = log_level_style(e.level);
                    let line = Line::from(vec![
                        Span::styled(
                            format!("[{}] ", e.timestamp.format("%H:%M:%S")),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(
                            format!("{} ", e.level),
                            level_style,
                        ),
                        Span::raw(&e.message),
                    ]);
                    ListItem::new(line)
                })
                .collect();

            let list = List::new(items).block(
                Block::default()
                    .title(format!(
                        "Investigation  [session: {}]",
                        &session.id.to_string()[..8]
                    ))
                    .borders(Borders::ALL),
            );
            frame.render_widget(list, area);
        }
    }
}

fn render_plan_tab(frame: &mut Frame, area: Rect, app: &App) {
    if app.plan_view.steps.is_empty() {
        let p = Paragraph::new(
            "No plan available yet.\n\n\
             Investigation must complete before a plan is proposed.",
        )
        .block(Block::default().title("Plan").borders(Borders::ALL))
        .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(p, area);
        return;
    }

    let overall_risk = app
        .plan_view
        .steps
        .iter()
        .map(|sv| sv.step.risk_tier)
        .max()
        .unwrap_or(RiskTier::Low);

    // Split: risk gauge on top, step list below.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    // Risk gauge.
    let risk_pct = risk_to_percent(overall_risk);
    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(format!("Overall Risk: {}", overall_risk))
                .borders(Borders::ALL),
        )
        .gauge_style(
            Style::default()
                .fg(risk_color(overall_risk))
                .bg(Color::Black),
        )
        .percent(risk_pct);
    frame.render_widget(gauge, chunks[0]);

    // Step table.
    let header_cells = ["#", "Description", "Capability", "Risk", "Status", "Approved"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow)));
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = app
        .plan_view
        .steps
        .iter()
        .enumerate()
        .map(|(i, sv)| {
            let selected = i == app.plan_view.selected_index;
            let row_style = if selected {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };
            Row::new([
                Cell::from(format!("{}", i + 1)),
                Cell::from(sv.step.description.clone()),
                Cell::from(sv.step.capability_id.clone()),
                Cell::from(sv.step.risk_tier.to_string())
                    .style(Style::default().fg(risk_color(sv.step.risk_tier))),
                Cell::from(step_status_str(&sv.step.status))
                    .style(step_status_style(&sv.step.status)),
                Cell::from(if sv.approved { "✓" } else { "" }),
            ])
            .style(row_style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(3),
            Constraint::Min(20),
            Constraint::Min(20),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title("Plan Steps  [a=approve-all  s=approve-step  r=reject]")
            .borders(Borders::ALL),
    );
    frame.render_widget(table, chunks[1]);
}

fn render_execution_tab(frame: &mut Frame, area: Rect, app: &App) {
    if app.plan_view.steps.is_empty() {
        let p = Paragraph::new("No execution in progress.")
            .block(Block::default().title("Execution").borders(Borders::ALL))
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(p, area);
        return;
    }

    let items: Vec<ListItem> = app
        .plan_view
        .steps
        .iter()
        .enumerate()
        .map(|(i, sv)| {
            let status_style = step_status_style(&sv.step.status);
            let line = Line::from(vec![
                Span::styled(
                    format!("  {:>2}. ", i + 1),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(sv.step.description.clone()),
                Span::styled(
                    format!("  [{}]", step_status_str(&sv.step.status)),
                    status_style,
                ),
            ]);
            ListItem::new(line)
        })
        .collect();

    let completed = app
        .plan_view
        .steps
        .iter()
        .filter(|sv| sv.step.status == StepStatus::Succeeded)
        .count();
    let total = app.plan_view.steps.len();

    let list = List::new(items).block(
        Block::default()
            .title(format!("Execution  [{}/{} steps complete]", completed, total))
            .borders(Borders::ALL),
    );
    frame.render_widget(list, area);
}

fn render_audit_tab(frame: &mut Frame, area: Rect, app: &App) {
    let content = match &app.session {
        None => "No session audit log available.".to_string(),
        Some(session) => format_session_audit(session),
    };

    let paragraph = Paragraph::new(content)
        .block(Block::default().title("Audit Log").borders(Borders::ALL))
        .scroll((app.log_scroll, 0))
        .style(Style::default().fg(Color::Gray));

    frame.render_widget(paragraph, area);
}

fn render_status_bar(frame: &mut Frame, area: Rect, app: &App) {
    let status = app.status_message.as_deref().unwrap_or("Ready");
    let shortcuts = "[Tab] tab  [q] quit  [a] approve-all  [s] approve-step  [r] reject  [j/k] scroll";
    let content = format!(" {}  |  {}", status, shortcuts);

    let paragraph = Paragraph::new(content)
        .style(Style::default().bg(Color::DarkGray).fg(Color::White))
        .alignment(Alignment::Left);

    frame.render_widget(paragraph, area);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn risk_color(tier: RiskTier) -> Color {
    match tier {
        RiskTier::Low => Color::Green,
        RiskTier::Medium => Color::Yellow,
        RiskTier::High => Color::Red,
        RiskTier::Critical => Color::Magenta,
    }
}

fn risk_to_percent(tier: RiskTier) -> u16 {
    match tier {
        RiskTier::Low => 10,
        RiskTier::Medium => 40,
        RiskTier::High => 70,
        RiskTier::Critical => 100,
    }
}

fn step_status_str(status: &StepStatus) -> &'static str {
    match status {
        StepStatus::Pending => "Pending",
        StepStatus::Running => "Running…",
        StepStatus::Succeeded => "Done",
        StepStatus::Failed { .. } => "Failed",
        StepStatus::Skipped => "Skipped",
        StepStatus::RolledBack => "Rolled Back",
    }
}

fn step_status_style(status: &StepStatus) -> Style {
    match status {
        StepStatus::Pending => Style::default().fg(Color::DarkGray),
        StepStatus::Running => Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
        StepStatus::Succeeded => Style::default().fg(Color::Green),
        StepStatus::Failed { .. } => Style::default()
            .fg(Color::Red)
            .add_modifier(Modifier::BOLD),
        StepStatus::Skipped => Style::default().fg(Color::Yellow),
        StepStatus::RolledBack => Style::default().fg(Color::Magenta),
    }
}

fn log_level_style(level: LogLevel) -> Style {
    match level {
        LogLevel::Info => Style::default().fg(Color::Cyan),
        LogLevel::Warn => Style::default().fg(Color::Yellow),
        LogLevel::Error => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        LogLevel::Debug => Style::default().fg(Color::DarkGray),
    }
}

fn format_session_audit(session: &Session) -> String {
    let mut out = String::new();
    out.push_str(&format!("Session ID : {}\n", session.id));
    out.push_str(&format!("Goal       : {}\n", session.goal));
    out.push_str(&format!("Host       : {}\n", session.host));
    out.push_str(&format!("Phase      : {:?}\n", session.phase));
    out.push_str(&format!(
        "Started    : {}\n",
        session.started_at.format("%Y-%m-%dT%H:%M:%SZ")
    ));
    if session.dry_run {
        out.push_str("Mode       : DRY-RUN\n");
    }
    out.push_str("\n── Event Log ──────────────────────────────────────────────────────\n");
    for entry in &session.log_entries {
        out.push_str(&format!(
            "[{}] {:5}  {}\n",
            entry.timestamp.format("%H:%M:%S"),
            entry.level,
            entry.message
        ));
    }
    out
}
