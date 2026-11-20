import Foundation

/// Access to the BSI WID / CERT-Bund CSAF provider (TLP:WHITE advisories).
/// https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json
public enum BSI {
    public static let feedURL = URL(string: "https://wid.cert-bund.de/.well-known/csaf/white/bsi-wid-white.json")!

    public static func portalURL(for advisoryID: String) -> URL? {
        // CSAF id "WID-SEC-W-2026-4165" ↔ portal name "WID-SEC-2026-4165"
        let name = advisoryID.replacingOccurrences(of: "WID-SEC-W-", with: "WID-SEC-")
        return URL(string: "https://wid.cert-bund.de/portal/wid/securityadvisory?name=\(name)")
    }
}

// MARK: - ROLIE feed (index of all advisories)

public struct BSIFeedEntry: Sendable, Hashable {
    public let id: String
    public let title: String
    public let published: Date?
    public let updated: Date?
    public let csafURL: URL
    /// Lower-cased vendor terms.
    public let vendors: Set<String>
    /// Lower-cased product_name terms.
    public let products: Set<String>
    public let cves: [String]
}

public struct BSIFeedIndex: Sendable {
    public let entries: [BSIFeedEntry]
    public let fetched: Date
    /// lower-cased product name → original spellings
    public let productSpellings: [String: Set<String>]
    /// lower-cased product name → entry indices
    private let byProduct: [String: [Int]]
    /// CVE id → entry indices
    private let byCVE: [String: [Int]]

    public init(entries: [BSIFeedEntry], fetched: Date, productSpellings: [String: Set<String>] = [:]) {
        self.entries = entries
        self.fetched = fetched
        self.productSpellings = productSpellings
        var byProduct: [String: [Int]] = [:]
        var byCVE: [String: [Int]] = [:]
        for (i, e) in entries.enumerated() {
            for p in e.products { byProduct[p, default: []].append(i) }
            for c in e.cves { byCVE[c, default: []].append(i) }
        }
        self.byProduct = byProduct
        self.byCVE = byCVE
    }

    public func entries(for ref: ProductRef, updatedSince cutoff: Date?) -> [BSIFeedEntry] {
        let vendor = ref.vendor.lowercased()
        return (byProduct[ref.product.lowercased()] ?? [])
            .map { entries[$0] }
            .filter { $0.vendors.contains(vendor) }
            .filter { entry in
                guard let cutoff else { return true }
                return (entry.updated ?? entry.published ?? .distantPast) >= cutoff
            }
    }

    public func entries(forCVE cve: String) -> [BSIFeedEntry] {
        (byCVE[cve.uppercased()] ?? []).map { entries[$0] }
    }

    public func entries(forProductLowercased product: String) -> [BSIFeedEntry] {
        (byProduct[product] ?? []).map { entries[$0] }
    }

    // MARK: Decoding

    private struct Feed: Decodable {
        let feed: Inner
        struct Inner: Decodable { let entry: [Entry] }
        struct Entry: Decodable {
            let id: String
            let title: String
            let published: String?
            let updated: String?
            let content: Content?
            let category: [Category]?
        }
        struct Content: Decodable { let src: String }
        struct Category: Decodable { let scheme: String; let term: String }
    }

    public static func decode(_ data: Data, fetched: Date) throws -> BSIFeedIndex {
        let feed = try JSONDecoder().decode(Feed.self, from: data)
        var spellings: [String: Set<String>] = [:]
        let entries: [BSIFeedEntry] = feed.feed.entry.compactMap { e in
            guard let src = e.content?.src, let url = URL(string: src) else { return nil }
            var vendors = Set<String>(), products = Set<String>(), cves: [String] = []
            for c in e.category ?? [] {
                if c.scheme.hasSuffix("?vendor") {
                    vendors.insert(c.term.lowercased())
                } else if c.scheme.hasSuffix("?product_name") {
                    let key = c.term.lowercased()
                    products.insert(key)
                    spellings[key, default: []].insert(c.term)
                } else if c.scheme.contains("cve.org") {
                    cves.append(c.term)
                }
            }
            return BSIFeedEntry(
                id: e.id, title: e.title,
                published: DateParsing.iso8601(e.published), updated: DateParsing.iso8601(e.updated),
                csafURL: url, vendors: vendors, products: products, cves: cves
            )
        }
        return BSIFeedIndex(entries: entries, fetched: fetched, productSpellings: spellings)
    }
}

// MARK: - CSAF document

/// The parts of a CSAF 2.0 document that are needed for version matching.
public struct CSAFAdvisory: Sendable {
    public struct Leaf: Sendable, Hashable {
        public let vendor: String
        public let productName: String
        /// "product_version_range", "product_version" or "product_name" (no version info)
        public let category: String
        /// Branch name, e.g. "Golden Gate <27.2"
        public let versionText: String
        public let productID: String
        /// Full product name, e.g. "Apple macOS Golden Gate <27.2"
        public let fullName: String
    }

    public let advisory: Advisory
    public let leaves: [Leaf]
    public let affectedIDs: Set<String>
    public let fixedIDs: Set<String>
    /// CVE id → product ids known affected by that specific CVE.
    public let affectedByCVE: [String: Set<String>]

    private struct Doc: Decodable {
        struct Document: Decodable {
            let title: String
            let aggregate_severity: Text?
            let tracking: Tracking
            let notes: [Note]?
            let references: [Reference]?
        }
        struct Text: Decodable { let text: String }
        struct Tracking: Decodable {
            let id: String
            let initial_release_date: String?
            let current_release_date: String?
        }
        struct Note: Decodable { let category: String; let text: String }
        struct Reference: Decodable { let summary: String?; let url: String }
        struct ProductTree: Decodable { let branches: [Branch]? }
        struct Branch: Decodable {
            let category: String
            let name: String
            let branches: [Branch]?
            let product: Product?
        }
        struct Product: Decodable { let product_id: String; let name: String }
        struct Vulnerability: Decodable {
            let cve: String?
            let product_status: Status?
        }
        struct Status: Decodable {
            let known_affected: [String]?
            let fixed: [String]?
            let first_fixed: [String]?
            let known_not_affected: [String]?
        }

        let document: Document
        let product_tree: ProductTree?
        let vulnerabilities: [Vulnerability]?
    }

    public static func decode(_ data: Data, csafURL: URL) throws -> CSAFAdvisory {
        let doc = try JSONDecoder().decode(Doc.self, from: data)
        var leaves: [Leaf] = []

        func walk(_ branches: [Doc.Branch], vendor: String?, product: String?) {
            for b in branches {
                var vendor = vendor, product = product
                switch b.category {
                case "vendor": vendor = b.name
                case "product_name": product = b.name
                default: break
                }
                if let p = b.product, let vendor, let product {
                    leaves.append(Leaf(vendor: vendor, productName: product, category: b.category,
                                       versionText: b.name, productID: p.product_id, fullName: p.name))
                }
                if let sub = b.branches { walk(sub, vendor: vendor, product: product) }
            }
        }
        walk(doc.product_tree?.branches ?? [], vendor: nil, product: nil)

        var affected = Set<String>(), fixed = Set<String>(), cves: [String] = []
        var byCVE: [String: Set<String>] = [:]
        for v in doc.vulnerabilities ?? [] {
            if let cve = v.cve {
                cves.append(cve)
                byCVE[cve, default: []].formUnion(v.product_status?.known_affected ?? [])
            }
            affected.formUnion(v.product_status?.known_affected ?? [])
            fixed.formUnion(v.product_status?.fixed ?? [])
            fixed.formUnion(v.product_status?.first_fixed ?? [])
            fixed.formUnion(v.product_status?.known_not_affected ?? [])
        }

        let d = doc.document
        let portal = d.references?
            .first { $0.summary?.contains("Portal") == true }
            .flatMap { URL(string: $0.url) } ?? BSI.portalURL(for: d.tracking.id)
        let advisory = Advisory(
            id: d.tracking.id,
            title: d.title,
            severity: Severity(bsiText: d.aggregate_severity?.text),
            published: DateParsing.iso8601(d.tracking.initial_release_date),
            updated: DateParsing.iso8601(d.tracking.current_release_date),
            summary: d.notes?.first { $0.category == "summary" }?.text,
            csafURL: csafURL,
            portalURL: portal,
            cves: Array(Set(cves)).sorted()
        )
        return CSAFAdvisory(advisory: advisory, leaves: leaves, affectedIDs: affected, fixedIDs: fixed, affectedByCVE: byCVE)
    }

    /// Evaluates whether `version` of `ref` is affected by this advisory.
    /// - Returns: the matching affected leaf and the fixed versions, or nil.
    /// Leaves of the product tree that describe `ref` on the Mac.
    public func leaves(for ref: ProductRef) -> [Leaf] {
        let vendor = ref.vendor.lowercased()
        let product = ref.product.lowercased()
        if Platform.isMobileOnlyTitle(advisory.title), vendor != "apple" { return [] }
        return leaves.filter { leaf in
            leaf.vendor.lowercased() == vendor
                && (leaf.productName.lowercased() == product
                    || leaf.productName.lowercased() == "\(vendor) \(product)")
        }
    }

    /// - Parameter cve: restrict the check to products affected by this CVE (nil = whole advisory).
    public struct Hit: Sendable {
        public let leaf: Leaf
        public let fixed: [String]
        /// Set when the match is formally correct but implausible (see `evaluate`).
        public let uncertainReason: String?
    }

    /// Evaluates whether `version` of `ref` is affected by this advisory.
    /// - Parameter cve: restrict the check to products affected by this CVE (nil = whole advisory).
    public func evaluate(ref: ProductRef, version: Version, cve: String? = nil) -> Hit? {
        let relevant = leaves(for: ref)
        guard !relevant.isEmpty else { return nil }
        let affectedIDs = cve.flatMap { affectedByCVE[$0] } ?? self.affectedIDs

        var affectedSpecs: [(VersionSpec, Leaf)] = []
        var fixedVersions: [(Version, String)] = []
        for leaf in relevant {
            let spec = VersionSpec.parse(leaf.versionText)
            if Platform.isForeign(leaf.versionText) { continue }
            if affectedIDs.contains(leaf.productID) {
                // Leaves without any version information cannot be evaluated reliably.
                if let spec, leaf.category != "product_name" { affectedSpecs.append((spec, leaf)) }
            } else if let exact = spec?.exactVersion,
                      leaf.category == "product_version" || fixedIDs.contains(leaf.productID) {
                fixedVersions.append((exact, leaf.versionText))
            }
        }
        guard !affectedSpecs.isEmpty else { return nil }
        // A "fixed" version that lies inside an affected range contradicts the advisory (e.g. ">=1.11" / "=1.11").
        fixedVersions.removeAll { fixed in affectedSpecs.contains { $0.0.matches(fixed.0) } }

        guard let match = AffectedEvaluator.matchingSpec(
            installed: version,
            affected: affectedSpecs.map(\.0),
            fixed: fixedVersions.map(\.0)
        ), let leaf = affectedSpecs.first(where: { $0.0 == match })?.1 else { return nil }

        var fixedTexts = fixedVersions.map(\.1)
        if fixedTexts.isEmpty {
            fixedTexts = affectedSpecs.compactMap { spec, _ in spec.upperBound.map { "\($0)" } }
        }
        let references = fixedVersions.map(\.0) + affectedSpecs.compactMap(\.0.upperBound)
        let reason = AffectedEvaluator.implausibility(installed: version, matched: match, references: references)
        return Hit(leaf: leaf, fixed: Array(Set(fixedTexts)).sorted(), uncertainReason: reason)
    }
}
