use std::io::{self, Cursor};
use std::ops::Deref;

use bytes::Bytes;
use ratatui::backend::{Backend, ClearType, CrosstermBackend, WindowSize};
use ratatui::buffer::Cell;
use ratatui::layout::{Constraint, Layout, Position, Rect, Size};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::Line;
use ratatui::widgets::{
    Block, BorderType, Borders, HighlightSpacing, List, ListItem, ListState, Paragraph,
};
use ratatui::{Terminal, TerminalOptions, Viewport};
use termwiz::input::{InputEvent, InputParser, KeyCode, Modifiers};
use tui_input::{Input, InputRequest};
use warpgate_common::eventhub::{EventSender, EventSubscription};
use warpgate_common::{SessionId, Target, TargetSSHOptions, WarpgateError};

use crate::server::session::Event;

const HEADER_HEIGHT: u16 = 6;

type MenuTerminal = Terminal<VirtualTerminalBackend>;

/// A virtual backend that renders to a buffer and fakes a terminal size
/// need this because `CrosstermBackend` checks PTY size by querying the actual local PTY
struct VirtualTerminalBackend {
    inner: CrosstermBackend<Cursor<Vec<u8>>>,
    size: Size,
    cursor_position: Position,
}

impl VirtualTerminalBackend {
    const fn new(size: Size) -> Self {
        Self {
            inner: CrosstermBackend::new(Cursor::new(Vec::new())),
            size,
            cursor_position: Position::ORIGIN,
        }
    }

    const fn set_size(&mut self, size: Size) {
        self.size = size;
    }

    /// Returns all output produced since the last call and resets the buffer.
    fn take_output(&mut self) -> Vec<u8> {
        let writer = self.inner.writer_mut();
        writer.set_position(0);
        std::mem::take(writer.get_mut())
    }
}

impl Backend for VirtualTerminalBackend {
    type Error = io::Error;

    fn draw<'a, I>(&mut self, content: I) -> io::Result<()>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        let mut last_cell: Option<(u16, u16)> = None;
        self.inner
            .draw(content.inspect(|(x, y, _)| last_cell = Some((*x, *y))))?;

        // Cursor is now behind the last drawn cell
        if let Some((x, y)) = last_cell {
            self.cursor_position = Position {
                x: x.saturating_add(1).min(self.size.width.saturating_sub(1)),
                y,
            };
        }
        Ok(())
    }

    fn hide_cursor(&mut self) -> io::Result<()> {
        self.inner.hide_cursor()
    }

    fn show_cursor(&mut self) -> io::Result<()> {
        self.inner.show_cursor()
    }

    fn get_cursor_position(&mut self) -> io::Result<Position> {
        Ok(self.cursor_position)
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> io::Result<()> {
        let position = position.into();
        self.cursor_position = position;
        self.inner.set_cursor_position(position)
    }

    fn clear(&mut self) -> io::Result<()> {
        self.inner.clear()
    }

    fn clear_region(&mut self, clear_type: ClearType) -> io::Result<()> {
        self.inner.clear_region(clear_type)
    }

    fn size(&self) -> io::Result<Size> {
        Ok(self.size)
    }

    fn window_size(&mut self) -> io::Result<WindowSize> {
        Ok(WindowSize {
            columns_rows: self.size,
            pixels: Size::new(0, 0),
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct DrawState {
    list_state: ListState,
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
    Selected(Target),
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
    terminal_width: u16,
    terminal_height: u16,
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
    pub fn new(
        mut entries: Vec<MenuEntry<T>>,
        username: String,
        terminal_width: u16,
        terminal_height: u16,
    ) -> Result<Self, WarpgateError> {
        entries.sort_by(|a, b| a.label.cmp(&b.label));
        let terminal = Terminal::with_options(
            VirtualTerminalBackend::new(Size::new(terminal_width, terminal_height)),
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
            terminal_width,
            terminal_height,
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
                (KeyCode::Char('k' | 'K'), Modifiers::NONE)
                | (KeyCode::UpArrow | KeyCode::ApplicationUpArrow, _) => {
                    self.move_up();
                    redraw = true;
                }
                (KeyCode::Char('j' | 'J'), Modifiers::NONE)
                | (KeyCode::DownArrow | KeyCode::ApplicationDownArrow, _) => {
                    self.move_down();
                    redraw = true;
                }
                (KeyCode::PageUp, _) => {
                    self.move_page_up();
                    redraw = true;
                }
                (KeyCode::PageDown, _) => {
                    self.move_page_down();
                    redraw = true;
                }
                (KeyCode::Enter, _) => {
                    let visible_indices = self.visible_indices();
                    let sel = self.list_state.selected().unwrap_or(0);
                    if let Some(&entry_idx) = visible_indices.get(sel) {
                        let selected = self.entries.get(entry_idx).map(|e| e.value.clone());
                        return selected.map(MenuInputResult::Selected);
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
                    .filter_map(|&i| self.entries.get(i))
                    .map(|e| ListItem::new(e.label.clone()))
                    .collect(),
            )
        };

        DrawState {
            list_state: std::mem::take(&mut self.list_state),
            username_display,
            filter_value: self.filter_input.value().to_string(),
            filter_cursor: self.filter_input.visual_cursor(),
            list_items,
            no_entry_msg,
        }
    }

    fn render_frame(&mut self, visible_indices: &[usize]) -> Result<String, WarpgateError> {
        let mut draw_state = self.build_draw_state(visible_indices);

        let area = Rect::new(0, 0, self.terminal_width, self.terminal_height);

        if area != self.last_area {
            self.terminal.backend_mut().set_size(area.as_size());
            self.terminal.resize(area)?;
            self.last_area = area;
        }

        self.terminal.draw(|frame| {
            let [header_area, body_area]: [Rect; 2] = {
                let areas =
                    Layout::vertical([Constraint::Length(HEADER_HEIGHT), Constraint::Min(1)])
                        .split(frame.area());
                #[allow(clippy::unwrap_used, reason = "hardcoded size")]
                areas.deref().try_into().unwrap()
            };

            let header_block = Block::default()
                .border_style(Style::default().fg(Color::DarkGray))
                .border_type(BorderType::Plain)
                .borders(Borders::BOTTOM);
            let header_block_area = header_block.inner(header_area);

            let [
                header_block_area_subdiv_0,
                _,
                header_block_area_subdiv_2,
                _,
                header_block_area_subdiv_4,
            ]: [Rect; 5] = {
                let header_block_area_subdivs =
                    Layout::vertical([Constraint::Length(1); 5].as_slice())
                        .split(header_block_area);
                #[allow(clippy::unwrap_used, reason = "hardcoded size")]
                header_block_area_subdivs.deref().try_into().unwrap()
            };
            frame.render_widget(header_block, header_area);

            frame.render_widget(
                Paragraph::new(
                    Line::from("↑ / ↓ / Enter to connect. Type to filter. Ctrl-C to exit.").gray(),
                ),
                header_block_area_subdiv_2,
            );

            let [title_col_0, title_col_1]: [Rect; 2] = {
                let title_cols = Layout::horizontal([
                    Constraint::Min(0),
                    Constraint::Length(draw_state.username_display.chars().count() as u16),
                ])
                .split(header_block_area_subdiv_0);

                #[allow(clippy::unwrap_used, reason = "hardcoded size")]
                title_cols.deref().try_into().unwrap()
            };

            frame.render_widget(Paragraph::new("Welcome to Warpgate"), title_col_0);
            frame.render_widget(
                Paragraph::new(Line::from(draw_state.username_display.clone().gray())),
                title_col_1,
            );

            let [filter_col_0, filter_col_1]: [Rect; 2] = {
                let filter_cols = Layout::horizontal([Constraint::Length(8), Constraint::Min(0)])
                    .split(header_block_area_subdiv_4);

                #[allow(clippy::unwrap_used, reason = "hardcoded size")]
                filter_cols.deref().try_into().unwrap()
            };

            frame.render_widget(Paragraph::new("Filter: "), filter_col_0);
            frame.render_widget(
                Paragraph::new(draw_state.filter_value.as_str()),
                filter_col_1,
            );
            frame.set_cursor_position((
                filter_col_1.x + draw_state.filter_cursor as u16,
                filter_col_1.y,
            ));

            if let Some(items) = draw_state.list_items.take() {
                let list = List::new(items)
                    .highlight_symbol(" → ")
                    .highlight_spacing(HighlightSpacing::Always)
                    .highlight_style(
                        Style::default()
                            .fg(Color::White)
                            .bg(Color::Blue)
                            .add_modifier(Modifier::BOLD),
                    );
                frame.render_stateful_widget(list, body_area, &mut draw_state.list_state);
            } else {
                frame.render_widget(Paragraph::new(draw_state.no_entry_msg), body_area);
            }
        })?;

        self.list_state = draw_state.list_state;

        let bytes = self.terminal.backend_mut().take_output();
        String::from_utf8(bytes).map_err(WarpgateError::other)
    }

    fn page_size(&self) -> usize {
        self.terminal_height.saturating_sub(HEADER_HEIGHT).max(1) as usize
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

    fn move_page_up(&mut self) {
        let visible_len = self.visible_indices().len();
        if visible_len == 0 {
            return;
        }
        let current = self.list_state.selected().unwrap_or(0);
        self.list_state
            .select(Some(current.saturating_sub(self.page_size())));
    }

    fn move_page_down(&mut self) {
        let visible_len = self.visible_indices().len();
        if visible_len == 0 {
            return;
        }
        let current = self.list_state.selected().unwrap_or(0);
        self.list_state
            .select(Some((current + self.page_size()).min(visible_len - 1)));
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
        let _ = self.terminal.backend_mut().take_output();
        self.terminal.show_cursor()?;
        let bytes = self.terminal.backend_mut().take_output();
        String::from_utf8(bytes).map_err(WarpgateError::other)
    }
}

pub fn spawn_target_menu_loop(
    id: SessionId,
    username: String,
    entries: Vec<(Target, TargetSSHOptions)>,
    mut subscription: EventSubscription<Event>,
    sender: EventSender<Event>,
    terminal_width: u16,
    terminal_height: u16,
) -> anyhow::Result<()> {
    let name = format!("SSH {id} target menu loop");
    tokio::task::Builder::new().name(&name).spawn(async move {
        if let Err(error) = run_target_menu_loop(
            entries,
            username,
            &mut subscription,
            &sender,
            terminal_width,
            terminal_height,
        )
        .await
        {
            tracing::error!(?error, "Target menu error");
            let _ = sender.send_once(Event::Menu(MenuEvent::Abort)).await;
        }
    })?;

    Ok(())
}

async fn run_target_menu_loop(
    entries: Vec<(Target, TargetSSHOptions)>,
    username: String,
    subscription: &mut EventSubscription<Event>,
    sender: &EventSender<Event>,
    terminal_width: u16,
    terminal_height: u16,
) -> Result<(), WarpgateError> {
    let mut menu = TargetMenu::new(
        entries
            .into_iter()
            .map(|(target, options)| MenuEntry {
                label: target.name.clone(),
                value: (target, options),
            })
            .collect(),
        username,
        terminal_width,
        terminal_height,
    )?;

    if sender
        .send_once(Event::Menu(MenuEvent::Render(Bytes::from(menu.render()?))))
        .await
        .is_err()
    {
        return Ok(());
    }

    while let Some(event) = subscription.recv().await {
        match event {
            Event::MenuRedraw(new_width, new_height) => {
                menu.terminal_width = new_width;
                menu.terminal_height = new_height;
                if sender
                    .send_once(Event::Menu(MenuEvent::Render(Bytes::from(menu.render()?))))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Event::AdminApprovalPending { .. } | Event::AdminApprovalResolved { .. } => {}
            Event::ConsoleInput(data) => {
                let action = match menu.handle_input(&data) {
                    None => None,
                    Some(MenuInputResult::Redraw) => {
                        Some(MenuEvent::Render(Bytes::from(menu.render()?)))
                    }
                    Some(MenuInputResult::Abort) => Some(MenuEvent::Abort),
                    Some(MenuInputResult::Selected((target, _options))) => {
                        Some(MenuEvent::Selected(target))
                    }
                };

                let terminal = matches!(action, Some(MenuEvent::Selected(..) | MenuEvent::Abort));

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
            | Event::Menu(_)
            | Event::ServerChannelOpenResult(_, _) => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_menu() -> TargetMenu<u32> {
        // Must work without a local TTY (Warpgate normally runs without one) -
        // this is what regressed in #2050.
        TargetMenu::new(
            vec![
                MenuEntry {
                    label: "alpha".into(),
                    value: 1,
                },
                MenuEntry {
                    label: "bravo".into(),
                    value: 2,
                },
            ],
            "user".into(),
            120,
            40,
        )
        .expect("menu creation should not require a local TTY")
    }

    #[test]
    fn renders_without_a_local_tty() {
        let mut menu = make_menu();
        let out = menu
            .render()
            .expect("rendering should not require a local TTY");
        assert!(out.contains("alpha"));
        assert!(out.contains("bravo"));
        assert!(out.contains("Warpgate"));
    }

    #[test]
    fn handles_input_and_selection() {
        let mut menu = make_menu();
        menu.render().expect("initial render failed");

        // Down arrow
        let result = menu.handle_input(b"\x1b[B");
        assert!(matches!(result, Some(MenuInputResult::Redraw)));
        menu.render().expect("redraw failed");

        // Enter selects the second entry
        let result = menu.handle_input(b"\r");
        assert!(matches!(result, Some(MenuInputResult::Selected(2))));
    }

    #[test]
    fn resize_renders_full_frame() {
        let mut menu = make_menu();
        menu.render().expect("initial render failed");

        menu.terminal_width = 80;
        menu.terminal_height = 24;
        let out = menu.render().expect("render after resize failed");
        assert!(out.contains("alpha"));
    }
}
