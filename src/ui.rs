use std::io;

use termion::raw::IntoRawMode;
use tui::backend::TermionBackend;
use tui::Terminal;

#[allow(unused_variables, unused_mut, unused)]
pub fn ui_test() {
    let stdout = io::stdout().into_raw_mode().unwrap();
    let backend = TermionBackend::new(stdout);
    let mut terminal = Terminal::new(backend).unwrap();
}
