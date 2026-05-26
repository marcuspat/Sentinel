//! Custom ratatui widgets for the Sentinel TUI.

use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Widget},
    Frame,
};

use sentinel_core::RiskTier;

use crate::app::{PlanStepView, StepStatus};

// ── RiskGauge ─────────────────────────────────────────────────────────────────

/// A horizontal gauge that visualises a `RiskTier` with appropriate colour.
///
/// # Example
/// ```ignore
/// let gauge = RiskGaugeWidget::new(RiskTier::High);
/// frame.render_widget(gauge, area);
/// ```
pub struct RiskGaugeWidget {
    tier: RiskTier,
    label: Option<String>,
}

impl RiskGaugeWidget {
    pub fn new(tier: RiskTier) -> Self {
        Self { tier, label: None }
    }

    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

impl Widget for RiskGaugeWidget {
    fn render(self, area: Rect, buf: &mut ratatui::buffer::Buffer) {
        let pct = risk_percent(self.tier);
        let color = risk_color(self.tier);
        let label = self
            .label
            .unwrap_or_else(|| format!("{} ({}%)", self.tier, pct));

        let gauge = Gauge::default()
            .block(Block::default().borders(Borders::NONE))
            .gauge_style(Style::default().fg(color).bg(Color::Black))
            .percent(pct)
            .label(label);

        gauge.render(area, buf);
    }
}

// ── PlanStepList ──────────────────────────────────────────────────────────────

/// A list widget that renders plan steps with risk colouring and status icons.
pub struct PlanStepListWidget<'a> {
    steps: &'a [PlanStepView],
    selected: usize,
    block: Option<Block<'a>>,
}

impl<'a> PlanStepListWidget<'a> {
    pub fn new(steps: &'a [PlanStepView], selected: usize) -> Self {
        Self {
            steps,
            selected,
            block: None,
        }
    }

    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }
}

impl<'a> Widget for PlanStepListWidget<'a> {
    fn render(self, area: Rect, buf: &mut ratatui::buffer::Buffer) {
        let items: Vec<ListItem> = self
            .steps
            .iter()
            .enumerate()
            .map(|(i, sv)| {
                let is_selected = i == self.selected;
                let risk_color = risk_color(sv.step.risk_tier);
                let status_icon = step_icon(&sv.step.status);
                let approved_mark = if sv.approved { "✓ " } else { "  " };

                let line = Line::from(vec![
                    Span::styled(
                        approved_mark,
                        Style::default().fg(Color::Green),
                    ),
                    Span::styled(
                        format!("{} ", status_icon),
                        step_icon_style(&sv.step.status),
                    ),
                    Span::styled(
                        format!("[{:8}] ", sv.step.risk_tier),
                        Style::default().fg(risk_color),
                    ),
                    Span::raw(sv.step.description.clone()),
                ]);

                let style = if is_selected {
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };

                ListItem::new(line).style(style)
            })
            .collect();

        let mut list = List::new(items);
        if let Some(block) = self.block {
            list = list.block(block);
        }
        list.render(area, buf);
    }
}

// ── ObservationList ───────────────────────────────────────────────────────────

/// A simple widget that renders the session's log entries.
pub struct ObservationListWidget {
    entries: Vec<String>,
    scroll: u16,
}

impl ObservationListWidget {
    pub fn new(entries: Vec<String>, scroll: u16) -> Self {
        Self { entries, scroll }
    }
}

impl Widget for ObservationListWidget {
    fn render(self, area: Rect, buf: &mut ratatui::buffer::Buffer) {
        let content = self.entries.join("\n");
        let paragraph = Paragraph::new(content)
            .block(
                Block::default()
                    .title("Observations")
                    .borders(Borders::ALL),
            )
            .scroll((self.scroll, 0))
            .style(Style::default().fg(Color::Gray));
        paragraph.render(area, buf);
    }
}

// ── Convenience render helpers ────────────────────────────────────────────────

/// Render a `RiskGaugeWidget` directly into a `Frame` at `area`.
pub fn render_risk_gauge(frame: &mut Frame, area: Rect, tier: RiskTier) {
    frame.render_widget(RiskGaugeWidget::new(tier), area);
}

/// Render a `PlanStepListWidget` into a `Frame` at `area`.
pub fn render_plan_step_list(
    frame: &mut Frame,
    area: Rect,
    steps: &[PlanStepView],
    selected: usize,
) {
    frame.render_widget(
        PlanStepListWidget::new(steps, selected).block(
            Block::default()
                .title("Plan Steps")
                .borders(Borders::ALL),
        ),
        area,
    );
}

// ── Private helpers ───────────────────────────────────────────────────────────

fn risk_color(tier: RiskTier) -> Color {
    match tier {
        RiskTier::Low => Color::Green,
        RiskTier::Medium => Color::Yellow,
        RiskTier::High => Color::Red,
        RiskTier::Critical => Color::Magenta,
    }
}

fn risk_percent(tier: RiskTier) -> u16 {
    match tier {
        RiskTier::Low => 10,
        RiskTier::Medium => 40,
        RiskTier::High => 70,
        RiskTier::Critical => 100,
    }
}

fn step_icon(status: &StepStatus) -> &'static str {
    match status {
        StepStatus::Pending => "○",
        StepStatus::Running => "◎",
        StepStatus::Succeeded => "●",
        StepStatus::Failed { .. } => "✗",
        StepStatus::Skipped => "–",
        StepStatus::RolledBack => "↩",
    }
}

fn step_icon_style(status: &StepStatus) -> Style {
    match status {
        StepStatus::Pending => Style::default().fg(Color::DarkGray),
        StepStatus::Running => Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
        StepStatus::Succeeded => Style::default().fg(Color::Green),
        StepStatus::Failed { .. } => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        StepStatus::Skipped => Style::default().fg(Color::Yellow),
        StepStatus::RolledBack => Style::default().fg(Color::Magenta),
    }
}
