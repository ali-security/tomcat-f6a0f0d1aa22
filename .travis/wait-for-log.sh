#!/bin/bash
# Travis archives job logs asynchronously; the harvester reads log.txt as soon as the job
# ends. Keep the job open (after_script, cannot change the build result) until this job's
# public log already contains the test summary, so the harvested log is complete.
# Prints a heartbeat on every poll so Travis's 10-minute no-output watchdog never fires.
URL="https://api.travis-ci.com/v3/job/${TRAVIS_JOB_ID}/log.txt"
MARK='SEAL TEST SUMMARY COMPLETE'
waited=0
while [ $waited -lt 900 ]; do
    if curl -fsSL "$URL" 2>/dev/null | grep -q "$MARK"; then
        echo "log archive contains the test summary (after ${waited}s)"
        exit 0
    fi
    echo "waiting for log archive... (${waited}s)"
    sleep 20
    waited=$((waited + 20))
done
echo "log archive still incomplete after ${waited}s"
