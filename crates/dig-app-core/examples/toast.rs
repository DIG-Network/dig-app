//! Raise one real OS notification, so a human can confirm the platform actually drew it.
//!
//! **This is a manual tool, not a test.** It asserts nothing and proves nothing on its own — the
//! only evidence it produces is a toast a person sees. It exists because the last step of a
//! notification cannot be checked in process: `Show` returning `Ok` is exactly what an unpackaged
//! Windows app gets when the toast is silently dropped for having no registered identity, which is
//! the failure this whole backend is shaped around (`notify::render`).
//!
//! ```text
//! cargo run -p dig-app-core --example toast
//! ```
//!
//! On Windows it also creates the Start Menu entry the identity rides on, the first time it runs.

use dig_app_core::notify::{native_notifier, Notification};

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let notification = Notification {
        title: "DIG — Funds received".to_string(),
        body: "Received 2.5 $DIG".to_string(),
        // The funds-received toast routes nowhere: it is an awareness signal with no destination.
        // Run the `out_of_funds_toast` example to exercise the routed path.
        route: None,
    };
    println!("showing: {} / {}", notification.title, notification.body);
    native_notifier().show(&notification);
    println!("shown — look at your notification area");
}
