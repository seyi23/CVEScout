import Foundation

/// Downloads public data (BSI CSAF, CISA KEV) and keeps it in ~/Library/Caches/CVEScout.
/// Only GET requests to the configured public sources are made; no local data is sent.
public final class DataCache: Sendable {
    public let directory: URL
    private let session: URLSession

    public init(directory: URL? = nil) {
        let base = directory ?? FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("CVEScout", isDirectory: true)
        self.directory = base
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 60
        config.timeoutIntervalForResource = 600
        config.httpAdditionalHeaders = ["User-Agent": "CVEScout (local macOS vulnerability check)"]
        self.session = URLSession(configuration: config)
    }

    public struct Entry: Sendable {
        public let data: Data
        public let fetched: Date
        public let fromCache: Bool
    }

    /// Returns cached data if younger than `maxAge` (nil = never expires), otherwise downloads it.
    /// Falls back to stale cache when the download fails.
    public func data(for url: URL, key: String, maxAge: TimeInterval?, forceRefresh: Bool = false,
                     headers: [String: String] = [:], throttle: RateLimiter? = nil) async throws -> Entry {
        let file = directory.appendingPathComponent(Self.sanitize(key))
        let cachedDate = (try? FileManager.default.attributesOfItem(atPath: file.path))?[.modificationDate] as? Date
        if !forceRefresh, let cachedDate, maxAge.map({ Date().timeIntervalSince(cachedDate) < $0 }) ?? true,
           let data = try? Data(contentsOf: file) {
            return Entry(data: data, fetched: cachedDate, fromCache: true)
        }
        do {
            await throttle?.wait()
            var request = URLRequest(url: url)
            for (k, v) in headers { request.setValue(v, forHTTPHeaderField: k) }
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                throw URLError(.badServerResponse)
            }
            try? data.write(to: file, options: .atomic)
            return Entry(data: data, fetched: Date(), fromCache: false)
        } catch {
            if let cachedDate, let data = try? Data(contentsOf: file) {
                return Entry(data: data, fetched: cachedDate, fromCache: true)
            }
            throw error
        }
    }

    public func clear() throws {
        let fm = FileManager.default
        for file in try fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil) {
            try fm.removeItem(at: file)
        }
    }

    static func sanitize(_ key: String) -> String {
        String(key.map { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "." ? $0 : "_" })
    }
}

enum DateParsing {
    static func iso8601(_ string: String?) -> Date? {
        guard let string else { return nil }
        if let d = try? Date(string, strategy: Date.ISO8601FormatStyle(includingFractionalSeconds: true)) { return d }
        return try? Date(string, strategy: Date.ISO8601FormatStyle())
    }
}
