import Foundation

/// Runs local read-only system tools (csrutil, spctl, fdesetup, …) without blocking the caller.
public enum Shell {
    public struct Result: Sendable {
        public let status: Int32
        /// stdout and stderr combined (several macOS tools print status to stderr).
        public let output: String
        public let timedOut: Bool
    }

    private final class ProcessBox: @unchecked Sendable {
        let process: Process
        private let lock = NSLock()
        private var _killed = false
        init(_ process: Process) { self.process = process }

        func kill() {
            lock.withLock {
                guard process.isRunning else { return }
                _killed = true
                process.terminate()
            }
        }

        var killed: Bool { lock.withLock { _killed } }
    }

    public static func run(_ executable: String, _ arguments: [String] = [], timeout: TimeInterval = 20) async -> Result? {
        guard FileManager.default.isExecutableFile(atPath: executable) else { return nil }
        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: executable)
                process.arguments = arguments
                process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "en_US.UTF-8"]
                let pipe = Pipe()
                process.standardOutput = pipe
                process.standardError = pipe
                process.standardInput = FileHandle.nullDevice
                do {
                    try process.run()
                } catch {
                    continuation.resume(returning: nil)
                    return
                }
                let box = ProcessBox(process)
                let killer = DispatchWorkItem { box.kill() }
                DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: killer)

                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                killer.cancel()
                let timedOut = box.killed
                continuation.resume(returning: Result(
                    status: process.terminationStatus,
                    output: String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines),
                    timedOut: timedOut
                ))
            }
        }
    }
}
