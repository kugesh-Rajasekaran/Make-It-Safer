// The window a click on a notification opens: what it is about, the fix,
// and a row per server with its button. Its text is plain labels (nothing in
// it is read as markup or links). A button reports its click to the service
// like a notification button, and the window stays open until you close it;
// the service then shows it again with a ✓ on that server.
import AppKit

struct Fact: Codable {
    let label: String
    let value: String
}

struct Row: Codable {
    let name: String
    let detail: String?
    let command: String?
    let button: Button?
    let opened: Bool?
}

struct Dialog: Codable {
    let id: String
    let title: String
    let verdict: String
    let level: String
    let facts: [Fact]?
    let fix: String?
    let command: String?
    let rows: [Row]?
    let refresh: Bool?
}

final class Dialogs: NSObject, NSWindowDelegate {
    private let width: CGFloat = 420 // inside the margins
    private var windows: [String: NSWindow] = [:]
    private let clicked: (_ id: String, _ action: String) -> Void

    init(clicked: @escaping (String, String) -> Void) {
        self.clicked = clicked
    }

    // Opens the dialog, or updates it in place when it is already open. A
    // refresh (after one of its buttons) only updates an open window and
    // leaves it behind the terminal the button just opened.
    func show(_ dialog: Dialog) {
        let refresh = dialog.refresh == true
        if refresh && windows[dialog.id] == nil {
            return // closed meanwhile
        }
        let window = windows[dialog.id] ?? makeWindow(dialog.id)
        let content = view(dialog) { [weak window] in window?.close() }
        window.contentView = content
        window.setContentSize(content.fittingSize)
        if refresh {
            return
        }
        if !window.isVisible {
            window.center()
        }
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    func windowWillClose(_ notification: Notification) {
        windows = windows.filter { $0.value !== notification.object as? NSWindow }
    }

    private func makeWindow(_ id: String) -> NSWindow {
        let window = NSWindow(contentRect: .zero, styleMask: [.titled, .closable], backing: .buffered, defer: true)
        window.title = "Make-It-Safer"
        window.isReleasedWhenClosed = false
        window.collectionBehavior = .moveToActiveSpace
        window.delegate = self
        windows[id] = window
        return window
    }

    // MARK: - Layout

    private func view(_ d: Dialog, close: @escaping () -> Void) -> NSView {
        let verdict = label(d.verdict, size: 12, weight: .bold, color: color(d.level))
        var parts: [NSView] = [line([label(d.title, size: 15, weight: .semibold, width: width - 110)], verdict)]
        if let facts = d.facts, !facts.isEmpty {
            parts.append(section("What it is", facts.map(fact)))
        }
        var fix: [NSView] = []
        if let text = d.fix {
            fix.append(label(text, color: .secondaryLabelColor, width: width))
        }
        if let command = d.command {
            fix.append(code(command, width: width - 16))
        }
        if !fix.isEmpty {
            parts.append(section("The fix", fix))
        }
        if let rows = d.rows, !rows.isEmpty {
            parts.append(section("What it affects", rows.map { server($0, id: d.id) }))
        }
        let done = Press("Close", close)
        done.keyEquivalent = "\u{1b}"
        parts.append(line([], done))

        let stack = column(parts, spacing: 18)
        stack.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
        for part in parts {
            part.widthAnchor.constraint(equalToConstant: width).isActive = true
        }
        return stack
    }

    private func section(_ title: String, _ views: [NSView]) -> NSView {
        column([label(title.uppercased(), size: 11, weight: .semibold, color: .tertiaryLabelColor)] + views, spacing: 8)
    }

    private func fact(_ f: Fact) -> NSView {
        let name = label(f.label, size: 12, color: .secondaryLabelColor)
        name.widthAnchor.constraint(equalToConstant: 160).isActive = true
        let row = NSStackView(views: [name, label(f.value, width: width - 168)])
        row.alignment = .firstBaseline
        return row
    }

    private func server(_ r: Row, id: String) -> NSView {
        var lines: [NSView] = [label(r.name, weight: .semibold)]
        if let detail = r.detail {
            lines.append(label(detail, size: 12, color: .secondaryLabelColor, width: width - 150))
        }
        if let command = r.command {
            lines.append(code(command, width: width - 166))
        }
        let button = r.button.map { b in
            Press(b.title + (r.opened == true ? " ✓" : "")) { [weak self] in self?.clicked(id, b.id) }
        }
        return line([column(lines, spacing: 3)], button)
    }

    // MARK: - Pieces

    // A row: views on the left, trailing at the right edge.
    private func line(_ views: [NSView], _ trailing: NSView?) -> NSStackView {
        let spacer = NSView()
        spacer.setContentHuggingPriority(.init(1), for: .horizontal)
        let row = NSStackView(views: views + [spacer] + [trailing].compactMap { $0 })
        row.alignment = .centerY
        return row
    }

    private func column(_ views: [NSView], spacing: CGFloat) -> NSStackView {
        let stack = NSStackView(views: views)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = spacing
        return stack
    }

    private func label(_ text: String, size: CGFloat = 13, weight: NSFont.Weight = .regular,
                       color: NSColor = .labelColor, width: CGFloat? = nil) -> NSTextField {
        let field = width == nil ? NSTextField(labelWithString: text) : NSTextField(wrappingLabelWithString: text)
        field.font = .systemFont(ofSize: size, weight: weight)
        field.textColor = color
        field.isSelectable = true
        if let width {
            field.preferredMaxLayoutWidth = width
        }
        return field
    }

    // A command, in a monospaced box you can select and copy from.
    private func code(_ text: String, width: CGFloat) -> NSView {
        let field = label(text, size: 11.5, width: width)
        field.font = .monospacedSystemFont(ofSize: 11.5, weight: .regular)
        let box = NSStackView(views: [field])
        box.edgeInsets = NSEdgeInsets(top: 6, left: 8, bottom: 6, right: 8)
        box.wantsLayer = true
        box.layer?.backgroundColor = NSColor.gray.withAlphaComponent(0.15).cgColor
        box.layer?.cornerRadius = 6
        return box
    }

    private func color(_ level: String) -> NSColor {
        switch level {
        case "urgent": return .systemRed
        case "high": return .systemOrange
        default: return .secondaryLabelColor
        }
    }
}

// A push button that runs a closure.
final class Press: NSButton {
    private var run: () -> Void = {}

    convenience init(_ title: String, _ run: @escaping () -> Void) {
        self.init(title: title, target: nil, action: nil)
        self.run = run
        target = self
        action = #selector(press)
        bezelStyle = .rounded
    }

    @objc private func press() { run() }
}
