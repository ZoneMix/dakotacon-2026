# Cloud Therapy Session -- DakotaCon 2026

A terminal-based presentation on cloud red teaming, covering 4 real-world attack stories from AWS engagements with live demos, prescriptions, and a Monday morning checklist.

Presented by **Bailey Belisario** ([@BBelisario20](https://x.com/BBelisario20)) at [DakotaCon 2026](https://dakotacon.org).

## Running the Presentation

This presentation is built for [Ostendo](https://github.com/ZoneMix/ostendo), a terminal presentation tool.

### Prerequisites

- [Kitty terminal](https://sw.kovidgoyal.net/kitty/) (recommended for images, font sizing, and animations)
- [Rust toolchain](https://rustup.rs/) (to build Ostendo)

### Install Ostendo

```bash
git clone https://github.com/ZoneMix/ostendo.git
cd ostendo
cargo build --release
```

### Run the Presentation

```bash
# From the ostendo directory:
./target/release/ostendo /path/to/dakotacon-2026/presentation.md

# Or with Kitty for best experience:
kitty -o allow_remote_control=yes -o font_size=24 --start-as=maximized \
  ./target/release/ostendo /path/to/dakotacon-2026/presentation.md
```

### Navigation

| Key | Action |
|-----|--------|
| Right / Space / Enter | Next slide |
| Left / Backspace | Previous slide |
| `g` + number + Enter | Jump to slide |
| `j` / `k` | Scroll down / up |
| `]` / `[` | Increase / decrease font |
| `Ctrl+E` | Execute code block |
| `h` | Help overlay |
| `q` | Quit |

## Live Demos

The `demos/` directory contains bash scripts for live AWS demos. These require:

- An AWS account with the demo infrastructure deployed
- AWS CLI profiles configured
- The demo scripts reference placeholder values (`<YOUR_PATH>`, `<YOUR_PROFILE>`) that must be replaced with your environment details

**The demos are designed for simulation mode by default.** To run live, create a `.demo_mode` file:

```bash
echo "live" > demos/.demo_mode
```

## Structure

```
presentation.md    # The full slide deck (66 slides)
demos/             # Live demo bash scripts
  demo_runner.sh   # Shared utility functions
  demo_config.sh   # Timing configuration
  story1_*.sh      # Story 1: Broken Deny Policy
  story2_*.sh      # Story 2: IMDS + Cross-Account Chain
  story3_*.sh      # Story 3: ECS Runner Exploit
  story4_*.sh      # Story 4: Detection & Response
assets/            # Images used in the presentation
```

## The 4 Stories

1. **Patient Denial** -- A deny policy using an unsupported condition key (`aws:ResourceTag` for S3) silently fails, giving full S3 access to terraform state files containing credentials.

2. **Patient Trust Issues** -- IMDS credential theft from an EKS node, followed by cross-account role chaining without ExternalId, reaching production admin.

3. **Patient Enablement** -- An ECS Fargate GitLab runner with AdministratorAccess to production, exploited via K8s service account impersonation and a malicious pipeline that dumps `/proc/self/environ`.

4. **Patient Selective Hearing** -- Detection that partially worked but failed to follow through. The blue team caught the symptom (abnormal login), removed it, but never investigated the root cause.

## Monday Morning Checklist

**PREVENT:**
1. Run IAM Access Analyzer
2. Enforce IMDSv2 everywhere
3. Add ExternalId to ALL trust policies
4. Scope IRSA to specific service accounts
5. Encrypt and isolate tfstate
6. Scope CI/CD runners to specific projects

**DETECT + RESPOND:**
7. Wire GuardDuty -> SNS -> your team
8. Write incident runbooks (before the alert fires)
9. Rotate all keys > 90 days
10. Enable AMSI on Windows
11. Separate prod, staging, and dev accounts
12. Build CloudTrail Insights queries

## Contact

- Website: [zonemix.tech](https://zonemix.tech)
- GitHub: [ZoneMix](https://github.com/ZoneMix)
- Neuvik: [neuvik.com](https://neuvik.com)

## License

GPL-3.0 -- see [LICENSE](LICENSE).
