// Editorial content for the blog. Each post renders on /blog/:slug.
export const POSTS = [
  {
    slug: "kev-epss-prioritization",
    title: "Stop drowning in findings: prioritise with CISA KEV and EPSS",
    excerpt: "A scanner that returns 400 issues is not helping you. Here's how we blend severity, exploitation-in-the-wild and predicted probability into a single fix-first order.",
    category: "Prioritization",
    date: "2026-07-18", read: "6 min", author: "Pentrixa Research", initials: "PR",
    body: [
      ["p", "Every security team has felt it: you run a scan, get hundreds of findings, and freeze. Which do you fix on a Tuesday afternoon with two hours to spare? CVSS alone won't tell you, a 9.8 that nobody is exploiting is often less urgent than a 7.5 that is being weaponised across the internet today."],
      ["h", "Three signals, one number"],
      ["p", "Pentrixa computes a 0–100 priority for every finding by combining three things. First, severity, the classic impact rating. Second, CISA's Known Exploited Vulnerabilities (KEV) catalog: if a CVE is on the KEV list, attackers are using it right now, so it jumps the queue. Third, FIRST's Exploit Prediction Scoring System (EPSS), which estimates the probability a vulnerability will be exploited in the next 30 days."],
      ["p", "The result is an order that matches reality: the five things most likely to get you breached float to the top, and the long tail of theoretical issues waits its turn."],
      ["h", "Confidence matters too"],
      ["p", "A finding is only as useful as your trust in it. Every Pentrixa result carries a confidence level, confirmed (proven with an exploit marker, timing or exact match), firm (a directly observed configuration fact), or tentative (a heuristic worth a human's eye). Priority blends confidence in, so a confirmed high beats a tentative critical."],
      ["quote", "“Fix these five” beats “here are four hundred” every single time."],
      ["p", "The point of a scanner is not to find the most issues. It's to change what you do on Monday morning. Prioritisation is what makes that happen."],
    ],
  },
  {
    slug: "owasp-2025-what-changed",
    title: "OWASP Top 10:2025, what actually changed, and why",
    excerpt: "The 2025 list reshuffles the web's most important risks. We walk through the movers, supply chain, misconfiguration, and the new exceptional-conditions category.",
    category: "Standards",
    date: "2026-07-10", read: "7 min", author: "Pentrixa Research", initials: "PR",
    body: [
      ["p", "The OWASP Top 10 is the closest thing the web has to a shared vocabulary for risk. The 2025 revision keeps the spirit of the list while promoting categories that reflect how breaches actually happen now."],
      ["h", "Supply chain steps forward"],
      ["p", "What used to be 'Vulnerable and Outdated Components' has broadened into Software Supply Chain Failures (A03). Dependency confusion, typosquatting, and compromised build pipelines are no longer edge cases, they are the main event. Pentrixa maps its SCA, dependency-confusion and CI/CD checks straight into this category."],
      ["h", "Misconfiguration climbs"],
      ["p", "Security Misconfiguration (A02) rises because cloud and container defaults are where so many real incidents begin: a public S3 bucket, an open security group, an exposed admin panel. A single toggle left wrong can undo months of careful code review."],
      ["h", "A home for the weird failures"],
      ["p", "The new Mishandling of Exceptional Conditions (A10) gives a home to the crashes, verbose errors and race-y edge cases that attackers love precisely because developers rarely test them."],
      ["p", "Pentrixa tags every finding with its 2025 category and renders a full scorecard, all ten categories, the ones you passed shown in green next to the ones that need work. Coverage you can see, not just a list of problems."],
    ],
  },
  {
    slug: "secrets-in-git-history",
    title: "The secret you deleted is still in your git history",
    excerpt: "Rotating a leaked key isn't optional, because removing it from the latest commit does nothing. A short, practical guide to leaked credentials.",
    category: "AppSec",
    date: "2026-06-29", read: "5 min", author: "Pentrixa Research", initials: "PR",
    body: [
      ["p", "It happens to the best teams. An API key gets committed, someone notices, and a follow-up commit quietly removes it. Crisis averted, except it isn't. Git never forgets: the key still sits in the history, one 'git log -p' away from anyone with repo access."],
      ["h", "Why removal is not enough"],
      ["p", "The only safe response to a leaked credential is to rotate it. Assume it is compromised the moment it lands in a commit, a build log, or a public bundle. Deleting the line changes nothing about the secret's validity, it just makes it slightly harder to find."],
      ["h", "What Pentrixa looks for"],
      ["p", "Our secrets scanner ships 37 provider detectors, AWS, GitHub, GitLab, Google, Slack, Stripe, OpenAI, Azure, and more, plus a Shannon-entropy heuristic for the generic high-entropy assignments that pattern-matching misses. Vendored directories, lock files and binaries are skipped so you get signal, not noise, and every match is redacted in the report so it never re-leaks."],
      ["quote", "Rotate first, clean history second. In that order."],
      ["p", "Better still, catch it before it merges. Wire a secrets scan into your pipeline and a leaked key becomes a failed check instead of an incident."],
    ],
  },
];

export const getPost = (slug) => POSTS.find((p) => p.slug === slug);
