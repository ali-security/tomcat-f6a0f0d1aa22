#!/usr/bin/env python3
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Print the JUnit results of `ant test` to the job log.

antTest.sh sends Ant's output to ant-test.log (Travis caps stdout), so the job log
otherwise carries no test results. This reads the plain-formatter reports
(TEST-<class>.<CONNECTOR>.txt) and prints one line per suite, every skipped test
with its reason (from the skip message, or from the @Ignore / Assume in the test
source when the message is empty or a bare assumption), every failure, and the
per-connector totals last.
"""

import glob
import os
import re
import sys

SUITE_RE = re.compile(r"^Testsuite: (\S+)")
TOTALS_RE = re.compile(
    r"^Tests run: (\d+), Failures: (\d+), Errors: (\d+), Skipped: (\d+)")
CASE_RE = re.compile(r"^Testcase: (\S+) took")
BARE_ASSUME_RE = re.compile(r"^(got: <|Expected: )|^$")


def source_for(cls):
    path = os.path.join("test", cls.split("$")[0].replace(".", "/") + ".java")
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()
    except OSError:
        return None


def method_body(lines, method):
    start = None
    for i, line in enumerate(lines):
        if re.search(r"\bvoid\s+" + re.escape(method) + r"\s*\(", line):
            start = i
            break
    if start is None:
        return None, None
    depth = 0
    seen = False
    end = len(lines)
    for j in range(start, len(lines)):
        depth += lines[j].count("{") - lines[j].count("}")
        if "{" in lines[j]:
            seen = True
        if seen and depth <= 0:
            end = j + 1
            break
    return start, lines[start:end]


def preceding_comment(lines, idx):
    comment = []
    for k in range(idx - 1, max(idx - 12, -1), -1):
        c = lines[k].strip()
        if c.startswith("@"):
            continue
        if c.startswith("//") or c.startswith("*") or c.startswith("/*"):
            text = c.lstrip("/*").strip()
            if text:
                comment.insert(0, text)
        else:
            break
    return " ".join(comment)[:300]


def source_reason(cls, method):
    lines = source_for(cls)
    if lines is None:
        return "test source not found"
    method = re.sub(r"\[.*\]$", "", method)
    start, body = method_body(lines, method)
    if start is not None:
        for k in range(start - 1, max(start - 6, -1), -1):
            s = lines[k].strip()
            if s.startswith("@Ignore"):
                comment = preceding_comment(lines, k)
                if s != "@Ignore" or comment:
                    return ("disabled upstream by method " + s +
                            ((" -- " + comment) if comment else ""))
                return ("disabled upstream by a bare @Ignore on the test method "
                        "(upstream gives no comment)")
            if s.endswith("}") or s.endswith(";"):
                break
        assumes = [b.strip() for b in body if "Assume." in b or "assume" in b]
        if assumes:
            return "assumption in test: " + " ".join(assumes)[:400]
    for idx, line in enumerate(lines):
        s = line.strip()
        if s.startswith("@Ignore") and any(
                "class " in lines[n] for n in range(idx, min(idx + 4, len(lines)))):
            comment = preceding_comment(lines, idx)
            inline = lines[idx].strip()
            return ("whole class disabled upstream by class-level " + inline +
                    ((" -- " + comment) if comment else ""))
    assumes = [l.strip() for l in lines if "Assume." in l]
    if assumes:
        return "assumption in class setup: " + " ".join(assumes)[:400]
    return "no reason given in test source"


def main(report_dir):
    totals = {}
    failures = []
    all_skips = []
    files = sorted(glob.glob(os.path.join(report_dir, "TEST-*.txt")))
    print("=" * 78)
    print("JUnit results (%d report files in %s)" % (len(files), report_dir))
    print("=" * 78)
    for path in files:
        name = os.path.basename(path)[5:-4]
        connector = name.rsplit(".", 1)[1] if "." in name else "?"
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        suite = None
        counts = None
        case = None
        skips = []
        for i, line in enumerate(lines):
            m = SUITE_RE.match(line)
            if m:
                suite = m.group(1)
                continue
            m = TOTALS_RE.match(line)
            if m and counts is None:
                counts = [int(x) for x in m.groups()]
                continue
            m = CASE_RE.match(line)
            if m:
                case = m.group(1)
                continue
            s = line.strip()
            if case and s.startswith("SKIPPED"):
                msg = s[len("SKIPPED"):].lstrip(":").strip()
                skips.append((case, msg))
            elif case and (s == "FAILED" or s == "Caused an ERROR"):
                detail = lines[i + 1].strip() if i + 1 < len(lines) else ""
                failures.append("%s [%s] %s: %s %s" % (suite, connector, case, s, detail))
        if counts is None:
            print("SUITE %-70s [%s] NO RESULTS" % (suite or name, connector))
            failures.append("%s [%s]: no results in report" % (suite or name, connector))
            continue
        run, fail, err, skip = counts
        t = totals.setdefault(connector, [0, 0, 0, 0, 0])
        t[0] += 1
        t[1] += run
        t[2] += fail
        t[3] += err
        t[4] += skip
        print("SUITE %s [%s] tests=%d passed=%d failures=%d errors=%d skipped=%d" % (
            suite, connector, run, run - fail - err - skip, fail, err, skip))
        if skip and not skips:
            skips.append((suite.rsplit(".", 1)[-1], ""))
        for case, msg in skips:
            reason = msg
            if BARE_ASSUME_RE.search(msg):
                src = source_reason(suite, case)
                reason = (msg + " | " + src) if msg else src
            short = case if case != suite else "(entire class)"
            print("    SKIPPED %s.%s -- %s" % (suite, short, reason))
            all_skips.append("SKIPPED [%s] %s.%s -- reason: %s" % (connector, suite, short, reason))
    print("=" * 78)
    print("ALL SKIPPED TESTS (%d), each with its reason:" % len(all_skips))
    for line in all_skips:
        print(line)
    print("=" * 78)
    if failures:
        print("FAILED / ERRORED TESTS:")
        for f in failures:
            print("    " + f)
    for connector in sorted(totals):
        suites, run, fail, err, skip = totals[connector]
        print("TOTAL [%s]: suites=%d tests=%d passed=%d failures=%d errors=%d skipped=%d" % (
            connector, suites, run, run - fail - err - skip, fail, err, skip))
    if not totals:
        print("TOTAL: no test reports found")
    print("SEAL TEST SUMMARY COMPLETE")
    return 1 if (failures or not totals) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "output/build/logs"))
