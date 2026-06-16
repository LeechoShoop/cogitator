use notify_rust::Notification;

pub fn send_alert(summary: &str, body: &str) {
    let mut n = Notification::new();

    n.summary(summary)
        .body(body)
        .timeout(5000);

    #[cfg(target_os = "windows")]
    {
        n.app_id("Cogitator.MachineSpirit");
    }
    if let Err(e) = n.show() {
        crate::logger::log_event(&format!("Notifier Error: {:?}", e));
    }
}