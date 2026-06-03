use std::io::Cursor;

use bytes::Bytes;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{HighlightSpacing, List, ListItem, ListState, Paragraph};
use ratatui::{Terminal, TerminalOptions, Viewport};
use termwiz::input::{InputEvent, InputParser, KeyCode, Modifiers};
use tui_input::{Input, InputRequest};
use warpgate_common::eventhub::{EventSender, EventSubscription};
use warpgate_common::{SessionId, Target, TargetSSHOptions, WarpgateError};

use crate::server::session::Event;

type MenuTerminal = Terminal<CrosstermBackend<Cursor<Vec<u8>>>>;

struct DrawState {
    list_state: ListState,
    header_lines: Vec<Line<'static>>,
    username_display: String,
    filter_value: String,
    filter_cursor: usize,
    list_items: Option<Vec<ListItem<'static>>>,
    no_entry_msg: &'static str,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum MenuEvent {
    Render(Bytes),
    Selected(Target, TargetSSHOptions),
    Abort,
}

pub struct TargetMenu<T: Clone> {
    entries: Vec<MenuEntry<T>>,
    filter_input: Input,
    list_state: ListState,
    input_parser: InputParser,
    username: String,
    terminal: MenuTerminal,
    last_area: Rect,
}

pub struct MenuEntry<T: Clone> {
    pub label: String,
    pub value: T,
}

pub enum MenuInputResult<T: Clone> {
    Redraw,
    Selected(T),
    Abort,
}

impl<T: Clone> TargetMenu<T> {
    pub fn new(mut entries: Vec<MenuEntry<T>>, username: String) -> Result<Self, WarpgateError> {
        entries.sort_by(|a, b| a.label.cmp(&b.label));
        let terminal = Terminal::with_options(
            CrosstermBackend::new(Cursor::new(Vec::new())),
            TerminalOptions {
                viewport: Viewport::Fixed(Rect::default()),
            },
        )?;
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Ok(Self {
            entries,
            filter_input: Input::default(),
            list_state,
            input_parser: InputParser::new(),
            username,
            terminal,
            last_area: Rect::default(),
        })
    }

    pub fn render(&mut self) -> Result<String, WarpgateError> {
        let visible_indices = self.visible_indices();
        self.render_frame(&visible_indices)
    }

    pub fn handle_input(&mut self, data: &[u8]) -> Option<MenuInputResult<T>> {
        let mut redraw = false;
        let mut events = vec![];
        self.input_parser
            .parse(data, |event| events.push(event), true);
        for event in events {
            let InputEvent::Key(key_event) = event else {
                continue;
            };
            match (key_event.key, key_event.modifiers) {
                (KeyCode::UpArrow | KeyCode::ApplicationUpArrow, _) => {
                    self.move_up();
                    redraw = true;
                }
                (KeyCode::DownArrow | KeyCode::ApplicationDownArrow, _) => {
                    self.move_down();
                    redraw = true;
                }
                (KeyCode::Enter, _) => {
                    let visible_indices = self.visible_indices();
                    let sel = self.list_state.selected().unwrap_or(0);
                    if let Some(&entry_idx) = visible_indices.get(sel) {
                        let selected = self.entries[entry_idx].value.clone();
                        return Some(MenuInputResult::Selected(selected));
                    }
                }
                (KeyCode::Backspace, _) => {
                    if !self.filter_input.value().is_empty() {
                        self.filter_input.handle(InputRequest::DeletePrevChar);
                        self.list_state.select(Some(0));
                        redraw = true;
                    }
                }
                (KeyCode::Delete, _) => {
                    if !self.filter_input.value().is_empty() {
                        self.filter_input.handle(InputRequest::DeleteNextChar);
                        self.list_state.select(Some(0));
                        redraw = true;
                    }
                }
                (KeyCode::Char('c'), modifiers) if modifiers.contains(Modifiers::CTRL) => {
                    return Some(MenuInputResult::Abort);
                }
                (KeyCode::Char('k' | 'K'), Modifiers::NONE) => {
                    self.move_up();
                    redraw = true;
                }
                (KeyCode::Char('j' | 'J'), Modifiers::NONE) => {
                    self.move_down();
                    redraw = true;
                }
                (KeyCode::Char(ch), Modifiers::NONE) if ch.is_ascii_graphic() || ch == ' ' => {
                    self.filter_input.handle(InputRequest::InsertChar(ch));
                    self.list_state.select(Some(0));
                    redraw = true;
                }
                _ => {}
            }
        }

        if redraw {
            Some(MenuInputResult::Redraw)
        } else {
            None
        }
    }

    fn build_draw_state(&mut self, visible_indices: &[usize]) -> DrawState {
        let username_display = format!(" {} ", self.username);
        let instructions =
            Line::from("↑/↓ / Enter to connect. Type to filter. Ctrl-C to exit.").gray();
        let header_lines: Vec<Line<'static>> = vec![
            Line::from(""),
            Line::from(""),
            instructions,
            Line::from(""),
            Line::from(""),
        ];

        let no_entry_msg: &'static str = if self.entries.is_empty() {
            "No authorized SSH targets are available for this account."
        } else {
            "No targets match the current filter."
        };

        let list_items = if visible_indices.is_empty() {
            None
        } else {
            Some(
                visible_indices
                    .iter()
                    .map(|&i| ListItem::new(self.entries[i].label.clone()))
                    .collect(),
            )
        };

        DrawState {
            list_state: std::mem::take(&mut self.list_state),
            header_lines,
            username_display,
            filter_value: self.filter_input.value().to_string(),
            filter_cursor: self.filter_input.visual_cursor(),
            list_items,
            no_entry_msg,
        }
    }

    fn render_frame(&mut self, visible_indices: &[usize]) -> Result<String, WarpgateError> {
        const HEADER_HEIGHT: u16 = 5;

        let mut draw_state = self.build_draw_state(visible_indices);

        let header_width = draw_state
            .header_lines
            .iter()
            .map(|l| l.to_string().chars().count())
            .max()
            .unwrap_or(0)
            .max(draw_state.username_display.chars().count())
            .max(9 + draw_state.filter_value.chars().count());
        let body_width = if draw_state.list_items.is_some() {
            visible_indices
                .iter()
                .map(|&i| self.entries[i].label.chars().count() + 2)
                .max()
                .unwrap_or(0)
        } else {
            draw_state.no_entry_msg.len()
        };
        let body_height = draw_state.list_items.as_ref().map_or(1, |v| v.len().max(1));

        let width = (header_width.max(body_width) as u16).max(40) + 2;
        let total_height = HEADER_HEIGHT + body_height as u16;
        let area = Rect::new(0, 0, width, total_height);

        {
            let w = self.terminal.backend_mut().writer_mut();
            w.get_mut().clear();
            w.set_position(0);
        }

        if area != self.last_area {
            self.terminal.resize(area)?;
            self.last_area = area;
        }

        self.terminal.draw(|frame| {
            let areas = Layout::vertical([Constraint::Length(HEADER_HEIGHT), Constraint::Min(1)])
                .split(frame.area());
            let header_area = areas[0];
            let body_area = areas[1];

            frame.render_widget(Paragraph::new(draw_state.header_lines.clone()), header_area);

            let title_row = Rect::new(header_area.x, header_area.y, header_area.width, 1);
            let title_cols = Layout::horizontal([
                Constraint::Min(0),
                Constraint::Length(draw_state.username_display.chars().count() as u16),
            ])
            .split(title_row);
            frame.render_widget(Paragraph::new("Welcome to Warpgate"), title_cols[0]);
            frame.render_widget(
                Paragraph::new(Line::from(draw_state.username_display.clone().gray())),
                title_cols[1],
            );

            let filter_row = Rect::new(
                header_area.x,
                header_area.y + HEADER_HEIGHT - 1,
                header_area.width,
                1,
            );
            let filter_cols =
                Layout::horizontal([Constraint::Length(8), Constraint::Min(0)]).split(filter_row);
            frame.render_widget(Paragraph::new("Filter: "), filter_cols[0]);
            frame.render_widget(
                Paragraph::new(draw_state.filter_value.as_str()),
                filter_cols[1],
            );
            frame.set_cursor_position((
                filter_cols[1].x + draw_state.filter_cursor as u16,
                filter_cols[1].y,
            ));

            if let Some(items) = draw_state.list_items.take() {
                let list = List::new(items)
                    .highlight_symbol(" → ")
                    .highlight_spacing(HighlightSpacing::Always)
                    .highlight_style(
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::LightCyan)
                            .add_modifier(Modifier::BOLD),
                    );
                frame.render_stateful_widget(list, body_area, &mut draw_state.list_state);
            } else {
                frame.render_widget(Paragraph::new(draw_state.no_entry_msg), body_area);
            }
        })?;

        self.list_state = draw_state.list_state;

        let bytes = self.terminal.backend().writer().get_ref().clone();
        String::from_utf8(bytes).map_err(WarpgateError::other)
    }

    fn move_up(&mut self) {
        let visible_len = self.visible_indices().len();
        if visible_len == 0 {
            return;
        }
        let current = self.list_state.selected().unwrap_or(0);
        self.list_state.select(Some(if current == 0 {
            visible_len - 1
        } else {
            current - 1
        }));
    }

    fn move_down(&mut self) {
        let visible_len = self.visible_indices().len();
        if visible_len == 0 {
            return;
        }
        let current = self.list_state.selected().unwrap_or(0);
        self.list_state.select(Some((current + 1) % visible_len));
    }

    fn visible_indices(&self) -> Vec<usize> {
        if self.filter_input.value().is_empty() {
            return (0..self.entries.len()).collect();
        }

        let needle = self.filter_input.value().to_ascii_lowercase();
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(idx, entry)| {
                if entry.label.to_ascii_lowercase().contains(&needle) {
                    Some(idx)
                } else {
                    None
                }
            })
            .collect()
    }

    /// restore terminal state
    pub fn cleanup(&mut self) -> Result<String, WarpgateError> {
        {
            let w = self.terminal.backend_mut().writer_mut();
            w.get_mut().clear();
            w.set_position(0);
        }
        self.terminal.show_cursor()?;
        let bytes = self.terminal.backend().writer().get_ref().clone();
        String::from_utf8(bytes).map_err(WarpgateError::other)
    }
}

pub fn spawn_target_menu_loop(
    id: SessionId,
    username: String,
    entries: Vec<(Target, TargetSSHOptions)>,
    mut subscription: EventSubscription<Event>,
    sender: EventSender<Event>,
) -> anyhow::Result<()> {
    let name = format!("SSH {id} target menu loop");
    tokio::task::Builder::new().name(&name).spawn(async move {
        let mut menu = TargetMenu::new(
            entries
                .into_iter()
                .map(|(target, options)| MenuEntry {
                    label: target.name.clone(),
                    value: (target, options),
                })
                .collect(),
            username,
        )?;

        if sender
            .send_once(Event::Menu(MenuEvent::Render(Bytes::from(menu.render()?))))
            .await
            .is_err()
        {
            return Ok::<(), WarpgateError>(());
        }

        while let Some(event) = subscription.recv().await {
            match event {
                Event::MenuRedraw => {
                    if sender
                        .send_once(Event::Menu(MenuEvent::Render(Bytes::from(menu.render()?))))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Event::ConsoleInput(data) => {
                    let action = match menu.handle_input(&data) {
                        None => None,
                        Some(MenuInputResult::Redraw) => {
                            Some(MenuEvent::Render(Bytes::from(menu.render()?)))
                        }
                        Some(MenuInputResult::Abort) => Some(MenuEvent::Abort),
                        Some(MenuInputResult::Selected((target, options))) => {
                            Some(MenuEvent::Selected(target, options))
                        }
                    };

                    let terminal = matches!(
                        action,
                        Some(MenuEvent::Selected(..)) | Some(MenuEvent::Abort)
                    );

                    if terminal {
                        // restore terminal state
                        if sender
                            .send_once(Event::Menu(MenuEvent::Render(Bytes::from(menu.cleanup()?))))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }

                    if let Some(action) = action
                        && sender.send_once(Event::Menu(action)).await.is_err()
                    {
                        break;
                    }

                    if terminal {
                        break;
                    }
                }
                Event::Command(_)
                | Event::ServerHandler(_)
                | Event::ServiceOutput(_)
                | Event::Client(_)
                | Event::Menu(_) => {}
            }
        }

        Ok(())
    })?;

    Ok(())
}
