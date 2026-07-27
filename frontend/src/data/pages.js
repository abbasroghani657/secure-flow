// Content for the standalone info pages linked from the nav and footer.
// Each entry: { eyebrow, title, intro, sections: [[heading, body]] }.
export const PAGES = {
  docs: {
    eyebrow: "Docs",
    title: "Getting started with Pentrixa",
    intro: "Everything you need to run your first scan and read the results. Most people are up and running in about a minute.",
    sections: [
      ["1. Add a target", "In the dashboard, open Targets and add a domain you own. You will be given a token to place as a DNS TXT record, an HTML meta tag, or a file at /.well-known. Once Pentrixa can see it, the target is verified and ready to scan."],
      ["2. Pick a scan type", "New Scan lists fifteen options. Point a web or deep scan at a verified URL, or upload a file for the offline scanners: an APK or IPA, a dependency manifest, an IaC file, a source archive, a container image, or an OpenAPI spec. Cloud posture takes read-only AWS keys."],
      ["3. Read the report", "Findings are grouped and ranked. Each one shows a severity, a confidence level, its OWASP category and CWE, the exact evidence, and a concrete fix. The OWASP tab gives you the full Top 10 scorecard at a glance."],
      ["4. Fix by priority", "Start at the top. The priority score blends severity with CISA KEV and EPSS, so the first few items are the ones most likely to be exploited. Re-scan to watch your score climb."],
      ["Scheduling and monitoring", "On paid plans you can schedule daily or weekly scans and get alerted when a new finding appears since the last run, so posture drift never goes unnoticed."],
    ],
  },
  about: {
    eyebrow: "About",
    title: "Security testing that respects your time",
    intro: "Pentrixa exists because most scanners bury the few things that matter under hundreds that do not. We built the tool we wanted: broad coverage, honest scope, and a report you can act on the same day.",
    sections: [
      ["What we believe", "A scanner should change what you do on Monday morning, not just generate a PDF. That means ruthless prioritisation, plain-language fixes, and never faking coverage we cannot actually deliver."],
      ["Honest by design", "Where a class of bug cannot be reliably auto-confirmed, we say so, and hand you a guided test recipe instead of a false all-clear. Honest scope protects you better than a green checkmark that was never earned."],
      ["Built on open standards", "Detection maps to OWASP 2025 and CWE; dependency data comes from OSV; prioritisation uses CISA KEV and FIRST EPSS. Open, auditable, and vendor-neutral."],
    ],
  },
  security: {
    eyebrow: "Security",
    title: "How we keep scanning safe",
    intro: "Running a security scanner should not create new risk. Here is how Pentrixa stays safe to run and defensible to own.",
    sections: [
      ["Authorised targets only", "You can only scan a domain after proving you control it, via DNS, a meta tag, or a well-known file. Scans of private and loopback addresses are blocked outright."],
      ["Non-destructive testing", "Active checks send crafted but harmless inputs. There is no brute forcing, no data modification, and no denial-of-service. Genuinely risky techniques are offered as guided manual playbooks, not fired automatically."],
      ["Your data does not linger", "Uploaded files, APKs, source archives and container images are analysed and then deleted. Cloud credentials are used only for that single scan and wiped afterward; they are never returned in any API response."],
      ["Transport and storage", "Traffic is served over TLS, secrets are kept out of logs, and authentication uses signed tokens with rate-limited endpoints."],
    ],
  },
  privacy: {
    eyebrow: "Legal",
    title: "Privacy Policy",
    intro: "This summary explains what Pentrixa collects and why. It is written to be readable; a full legal version is available on request.",
    sections: [
      ["What we collect", "Account details you provide (name, email), the targets you add, and the results of scans you run. We do not sell personal data."],
      ["Uploaded artifacts", "Files you upload for a scan (APK, IPA, source, IaC, container images) are processed to produce findings and then deleted. We do not retain your source code or binaries."],
      ["Credentials", "Cloud keys and session cookies you supply for a scan are used only for that scan and are wiped immediately afterward."],
      ["Your rights", "You can export or delete your account data at any time. Contact us and we will action requests promptly."],
    ],
  },
  terms: {
    eyebrow: "Legal",
    title: "Terms of Service",
    intro: "The short version: only scan what you are allowed to, and use the results responsibly.",
    sections: [
      ["Authorised use", "You may only scan systems you own or have explicit written permission to test. Unauthorised scanning may be illegal, and it is a breach of these terms."],
      ["Acceptable use", "Do not use Pentrixa to attack, disrupt, or exfiltrate data from systems, or to break any applicable law. Findings are provided to help you fix issues, not to weaponise them."],
      ["No warranty", "A passing scan does not guarantee the absence of vulnerabilities. Security is ongoing; treat Pentrixa as one layer, not a certificate."],
      ["Accounts", "You are responsible for activity under your account. Plans are month-to-month and can be cancelled at any time."],
    ],
  },
  changelog: {
    eyebrow: "Changelog",
    title: "What's new",
    intro: "A running log of what we have shipped. Newest first.",
    sections: [
      ["Container image scanning", "Upload a docker save tar and get OS-package CVEs per layer (Debian, Ubuntu, Alpine via OSV), plus secrets baked into layers and runs-as-root config checks."],
      ["Cloud posture, deepened", "AWS CSPM now covers root MFA, VPC flow logs, GuardDuty, KMS key rotation and secrets in Lambda environment variables, on top of S3, security groups, IAM and RDS."],
      ["SAST across ten languages", "Added C#, Kotlin and Swift, and deepened JavaScript and TypeScript to twenty-nine vulnerability classes with a low false-positive AST pass for Python."],
      ["Fix-first prioritisation", "Every finding now carries a confidence level and a priority score blended from severity, CISA KEV and EPSS, so the report leads with what is actually being exploited."],
      ["Full OWASP scorecard", "Results show all ten OWASP categories, clean ones included, so coverage is visible at a glance instead of only listing what failed."],
    ],
  },
};
