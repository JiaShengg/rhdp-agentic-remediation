# Phase 3 - BenchmarkJava + Maven primer

## What we set up

| Item | Value |
|---|---|
| Upstream | https://github.com/OWASP-Benchmark/BenchmarkJava |
| Local clone | `~/BenchmarkJava` |
| Build tool | Apache Maven 3.10.1 + Homebrew OpenJDK |
| POM check | `mvn -q -DskipTests compile` → OK |
| Golden TP | `BenchmarkTest00024` (sqli, real=true, CWE-89) |
| Golden FP | `BenchmarkTest00052` (sqli, real=false, CWE-89) |
| Catalog for Phase 4 | `lab/phase3-golden-findings.json` |

## Maven in one page (what you need for this demo)

**Maven** = build tool for Java. Like `npm` for Node, but for Java jars/wars.

| Concept | Meaning |
|---|---|
| `pom.xml` | Project Object Model - dependencies, plugins, how to build |
| `groupId` / `artifactId` / `version` | Coordinates of this project (`org.owasp:benchmark:1.2`) |
| `packaging: war` | Builds a web app archive (servlets), not a plain jar |
| `mvn -q -DskipTests compile` | Check POM is sane (what we ran) |
| `mvn compile` | Compile Java sources |
| `mvn test` | Run unit tests |
| `mvn package` | Produce the `.war` (heavy for full Benchmark) |
| `mvn -q` | Quiet logs |
| `mvn -DskipTests …` | Skip tests for speed |

**Why the agent needs Maven:** after Hermes patches a file, `run_maven` is the verifier. Green compile/test = “fixed” is credible; red = stay “open”.

**Demo practicality:** do **not** run full Benchmark `mvn package` in the live demo (thousands of testcases, long). Prefer scoped compile of touched sources, or a small smoke script Hermes calls. Full suite can be overnight soak.

## Local commands (your Mac)

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk
export PATH="$JAVA_HOME/bin:/opt/homebrew/opt/maven/bin:$PATH"

cd ~/BenchmarkJava
mvn -q -DskipTests compile
# later, when agent patches:
# mvn -DskipTests compile
```

Note: Temurin 17 cask needed sudo (skipped). Homebrew `openjdk` works for validate/compile.

## How ground truth works (FP story)

File `expectedresults-1.2.csv`:

```text
test name, category, real vulnerability, cwe
BenchmarkTest00024, sqli, true,  89   ← real bug → agent should fix
BenchmarkTest00052, sqli, false, 89   ← FP trap → agent should abstain
```

If a scanner (or our stub) reports 00052, that alert is a **false positive** relative to Benchmark. That is TC-05.

## Intentionally not in Phase 3

- Full `mvn package` / run Tomcat
- Stub MCP server (Phase 4)
- Hermes deploy (Phase 5)
- Actually patching 00024 (Phase 6)
