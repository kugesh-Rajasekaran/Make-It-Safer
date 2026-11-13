// Make-It-Safer Notifier shows Make-It-Safer's notifications, with buttons,
// and tells the background service which button you clicked.
//
// It connects to the service's Unix socket (the first argument, or
// ~/Library/Application Support/MakeItSafer/notify.sock) and exchanges one
// JSON message per line:
//   from the service: {"op":"show", id, title, body, buttons, sound}, {"op":"remove", id},
//                     {"op":"dialog", id, dialog} (Dialog.swift)
//                     and {"op":"settings"} (report the current permission now)
//   to the service:   {"op":"action", id, action, fromDialog} and {"op":"settings", authorized, alertStyle}
//
// The permission is reported on connect, on request and after every
// notification, so a change in System Settings is seen without a restart.
//
// macOS closes a notification when you click one of its buttons; the
// service then shows it again with a ✓ on that server.
import AppKit
import Foundation
import UserNotifications

struct Button: Codable {
    let id: String
    let title: String
}

struct Message: Codable {
    var op: String
    var id: String?
    var title: String?
    var body: String?
    var buttons: [Button]?
    var urgent: Bool?
    var sound: Bool?
    var dialog: Dialog?
    var action: String?
    var fromDialog: Bool?
    var authorized: Bool?
    var alertStyle: String?
}

final class Bridge: NSObject, UNUserNotificationCenterDelegate {
    private let socketPath: String
    private let center = UNUserNotificationCenter.current()
    private var link: FileHandle?
    private var buffer = Data()
    private var categories: [String: UNNotificationCategory] = [:]
    // Notifications asked for before the categories macOS already has were read.
    private var categoriesRead = false
    private var waiting: [Message] = []
    private lazy var dialogs = Dialogs { [weak self] id, action in
        self?.send(Message(op: "action", id: id, action: action, fromDialog: true))
    }

    init(socketPath: String) {
        self.socketPath = socketPath
        super.init()
    }

    func start() {
        center.delegate = self
        center.requestAuthorization(options: [.alert, .sound]) { _, _ in
            DispatchQueue.main.async { self.reportSettings() }
        }
        // macOS keeps the categories of earlier runs. setNotificationCategories
        // replaces them all, so start from what is registered and add to it:
        // only the categories of notifications still on screen, so the set
        // doesn't grow with every notification ever shown.
        center.getNotificationCategories { registered in
            self.center.getDeliveredNotifications { delivered in
                let live = Set(delivered.map { "mis." + $0.request.identifier })
                DispatchQueue.main.async { self.adopt(registered.filter { live.contains($0.identifier) }) }
            }
        }
        // Notifications wait for that answer; don't let them wait forever. If it
        // comes later after all, adopting again is harmless.
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in
            guard let self, !self.categoriesRead else { return }
            self.adopt([])
        }
        connect()
    }

    private func adopt(_ registered: Set<UNNotificationCategory>) {
        for category in registered where category.identifier.hasPrefix("mis.") && categories[category.identifier] == nil {
            categories[category.identifier] = category
        }
        categoriesRead = true
        let queued = waiting
        waiting.removeAll()
        for message in queued {
            dispatch(message)
        }
    }

    // MARK: - Socket

    private func connect() {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return retry() }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let path = Array(socketPath.utf8)
        guard path.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            close(fd)
            return
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: path)
            raw[path.count] = 0
        }
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, size) }
        }
        guard result == 0 else {
            close(fd)
            return retry()
        }

        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        handle.readabilityHandler = { [weak self] h in
            let data = h.availableData
            if data.isEmpty {
                h.readabilityHandler = nil // at the end of the stream the handler would otherwise fire again and again
            }
            DispatchQueue.main.async {
                // Anything still queued from a link that has been replaced is ignored.
                guard let self, self.link === h else { return }
                if data.isEmpty {
                    self.disconnected()
                } else {
                    self.received(data)
                }
            }
        }
        link = handle
        reportSettings()
    }

    private func retry() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
            self?.connect()
        }
    }

    private func disconnected() {
        link?.readabilityHandler = nil
        link = nil
        buffer.removeAll()
        retry()
    }

    private func received(_ data: Data) {
        buffer.append(data)
        while let newline = buffer.firstIndex(of: 0x0A) {
            let line = buffer.subdata(in: buffer.startIndex..<newline)
            buffer.removeSubrange(buffer.startIndex...newline)
            if let message = try? JSONDecoder().decode(Message.self, from: line) {
                dispatch(message)
            }
        }
    }

    private func send(_ message: Message) {
        guard let link, var data = try? JSONEncoder().encode(message) else { return }
        data.append(0x0A)
        do {
            try link.write(contentsOf: data)
        } catch {
            disconnected()
        }
    }

    // MARK: - Notifications

    private func dispatch(_ message: Message) {
        if !categoriesRead && (message.op == "show" || message.op == "remove") {
            waiting.append(message) // in order, once the categories are known
            return
        }
        switch message.op {
        case "show":
            show(message)
            reportSettings()
        case "settings":
            reportSettings()
        case "dialog":
            if let dialog = message.dialog {
                dialogs.show(dialog)
            }
        case "remove":
            if let id = message.id {
                categories.removeValue(forKey: "mis." + id)
                center.removeDeliveredNotifications(withIdentifiers: [id])
                center.removePendingNotificationRequests(withIdentifiers: [id])
            }
        default:
            break
        }
    }

    private func show(_ message: Message) {
        guard let id = message.id else { return }
        let category = "mis." + id
        let actions = (message.buttons ?? []).map {
            UNNotificationAction(identifier: $0.id, title: $0.title, options: [])
        }
        categories[category] = UNNotificationCategory(
            identifier: category, actions: actions, intentIdentifiers: [], options: [.customDismissAction])
        center.setNotificationCategories(Set(categories.values))

        let content = UNMutableNotificationContent()
        content.title = message.title ?? ""
        content.body = message.body ?? ""
        content.categoryIdentifier = category
        if message.sound == true {
            content.sound = .default
        }
        // The same identifier replaces the earlier notification.
        center.add(UNNotificationRequest(identifier: id, content: content, trigger: nil))
    }

    private func reportSettings() {
        center.getNotificationSettings { settings in
            let style: String
            switch settings.alertStyle {
            case .alert: style = "alert"
            case .banner: style = "banner"
            default: style = "none"
            }
            let authorized = settings.authorizationStatus == .authorized
            DispatchQueue.main.async {
                self.send(Message(op: "settings", authorized: authorized, alertStyle: style))
            }
        }
    }

    // A click on the notification or one of its buttons.
    func userNotificationCenter(
        _ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let id = response.notification.request.identifier
        var action = response.actionIdentifier
        if action == UNNotificationDefaultActionIdentifier {
            action = "default"
        }
        if action != UNNotificationDismissActionIdentifier {
            DispatchQueue.main.async {
                self.send(Message(op: "action", id: id, action: action))
            }
        }
        completionHandler()
    }

    // Show notifications even if this app happens to be frontmost.
    func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .list, .sound])
    }
}

let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
let socketPath = CommandLine.arguments.count > 1
    ? CommandLine.arguments[1]
    : support.appendingPathComponent("MakeItSafer/notify.sock").path

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let bridge = Bridge(socketPath: socketPath)
bridge.start()
app.run()
