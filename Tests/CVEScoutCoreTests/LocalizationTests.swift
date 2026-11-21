@testable import CVEScoutCore
import Foundation
import Testing

@Suite("Language selection")
struct LocalizationTests {
    @Test func systemLanguage() {
        #expect(Language.detect(arguments: [], environment: [:], setting: nil, preferred: ["de-DE", "en-US"]) == .de)
        #expect(Language.detect(arguments: [], environment: [:], setting: nil, preferred: ["en-GB"]) == .en)
        // Unsupported languages fall back to English.
        #expect(Language.detect(arguments: [], environment: [:], setting: nil, preferred: ["fr-FR", "de-DE"]) == .en)
        #expect(Language.detect(arguments: [], environment: [:], setting: nil, preferred: []) == .en)
    }

    @Test func precedence() {
        let preferred = ["de-DE"]
        #expect(Language.detect(arguments: [], environment: [:], setting: "en", preferred: preferred) == .en)
        #expect(Language.detect(arguments: [], environment: ["CVESCOUT_LANG": "en"], setting: "de", preferred: preferred) == .en)
        #expect(Language.detect(arguments: ["cvescout", "--lang", "de"], environment: ["CVESCOUT_LANG": "en"], setting: "en", preferred: ["en"]) == .de)
        #expect(Language.detect(arguments: [], environment: [:], setting: "system", preferred: preferred) == .de)
    }
}
