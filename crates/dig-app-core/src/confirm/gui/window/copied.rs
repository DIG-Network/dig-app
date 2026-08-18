//! The transient *Copied* acknowledgement, shared by every surface that puts a value on the
//! clipboard.
//!
//! # Why a clock and not a countdown
//!
//! An immediate-mode surface has no frame loop of its own to tick, so the acknowledgement is a
//! moment remembered and compared against the current time rather than a timer that counts down. A
//! repaint is requested for the instant it expires, so the label reverts on its own even when
//! nothing else on the window changes.
//!
//! # Why it is shared
//!
//! Two surfaces copy values — the Wallet pane's copy control and the prompt window's bare
//! identifier — and an acknowledgement that lasted different lengths on each would read as one of
//! them being broken. One constant, one pair of functions, one behaviour.

use egui::Ui;

/// How long a control reads *Copied* before returning to its resting label, in seconds.
///
/// Long enough to be seen after the eye returns from wherever it was pasting, short enough that the
/// control is honest about its resting state by the time anyone looks again.
pub(crate) const CONFIRMATION: f64 = 1.6;

/// Whether `element` copied something recently enough to still be acknowledging it.
pub(crate) fn confirming(ui: &Ui, element: egui::Id) -> bool {
    let now = ui.input(|i| i.time);
    let at: Option<f64> = ui.ctx().data(|d| d.get_temp(element));
    match at {
        Some(at) if now - at < CONFIRMATION => {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_secs_f64(
                    CONFIRMATION - (now - at),
                ));
            true
        }
        _ => false,
    }
}

/// Record that `element` just copied, so the next frames show the acknowledgement.
pub(crate) fn remember(ui: &Ui, element: egui::Id) {
    let now = ui.input(|i| i.time);
    ui.ctx().data_mut(|d| d.insert_temp(element, now));
}
