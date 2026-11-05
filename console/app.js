(function () {
  "use strict";

  const AUTO_REFRESH_MS = 5000;
  const STORAGE_KEY = "s3chaos.console.root";
  const STORAGE_USER_SET_KEY = "s3chaos.console.root.userSet";
  const MAX_TIMELINE_EVENTS = 80;
  const MAX_ARTIFACT_LINKS = 40;
  const LEGACY_FIELD_ALIASES = {
    artifactDir: ["artifact_dir"],
    artifactLinks: ["artifact_links"],
    artifactRoot: ["artifact_root"],
    artifactWarnings: ["artifact_warnings"],
    artifactsDir: ["artifacts_dir"],
    atMs: ["at_ms"],
    attemptArtifactDir: ["attempt_artifact_dir"],
    attemptArtifactsDir: ["attempt_artifacts_dir"],
    caseArtifactDir: ["case_artifact_dir"],
    caseName: ["case_name"],
    clusterTimeoutSeconds: ["cluster_timeout_seconds"],
    continueOnSeverities: ["continue_on_severities"],
    currentFailure: ["current_failure"],
    currentConfig: ["current_config"],
    currentStage: ["current_stage"],
    dataCorrectness: ["data_correctness"],
    dataLoss: ["data_loss"],
    elapsedSeconds: ["elapsed_seconds"],
    endedAtMs: ["ended_at_ms"],
    eventArtifact: ["event_artifact"],
    eventStream: ["event_stream"],
    eventTimeline: ["event_timeline"],
    evidenceClassifications: ["evidence_classifications"],
    exitCode: ["exit_code"],
    exitCodes: ["exit_codes"],
    failureSummary: ["failure_summary"],
    faultDurationSeconds: ["fault_duration_seconds"],
    healthGuardFailed: ["health_guard_failed"],
    maxClientDisruptions: ["max_client_disruptions"],
    maxDurationSeconds: ["max_duration_seconds"],
    minimumRequiredSeconds: ["minimum_required_seconds"],
    objectCount: ["object_count"],
    operationMix: ["operation_mix"],
    operationWeights: ["operation_weights"],
    payloadDistribution: ["payload_distribution"],
    prefillConcurrency: ["prefill_concurrency"],
    recoveredWithinSeconds: ["recovered_within_seconds"],
    recoveredWithinWindow: ["recovered_within_window"],
    recoveryStableWindowSeconds: ["recovery_stable_window_seconds"],
    recoveryStabilityRereadSeconds: ["recovery_stability_reread_seconds"],
    recoveryTimeoutSeconds: ["recovery_timeout_seconds"],
    remainingAfterMinimumSeconds: ["remaining_after_minimum_seconds"],
    remainingBeforeSeconds: ["remaining_before_seconds"],
    requestTimeoutSeconds: ["request_timeout_seconds"],
    runId: ["run_id"],
    runnerFailures: ["runner_failures"],
    rustFailureSummaryPresent: ["rust_failure_summary_present"],
    startedAtMs: ["started_at_ms"],
    stoppedSuite: ["stopped_suite"],
    stopOnFirstFailure: ["stop_on_first_failure"],
    stopReason: ["stop_reason"],
    suiteBudgetFailed: ["suite_budget_failed"],
    suiteLog: ["suite_log"],
    suitePlan: ["suite_plan"],
    suiteSummary: ["suite_summary"],
    suiteSummaryPresent: ["suite_summary_present"],
    testLog: ["test_log"],
    timeMs: ["time_ms"],
    totalClientDisruptions: ["total_client_disruptions"],
    workloadProfile: ["workload_profile"],
    failureIndex: ["failure_index"],
  };

  const dom = {};
  const state = {
    root: "",
    rootExplicit: false,
    snapshot: null,
    loading: false,
    error: null,
    autoTimer: null,
    lastLoadedAt: null,
    report: null,
    historyOffset: 0,
    historyLimit: 20,
    historyTotal: 0,
    historyRequest: 0,
  };

  document.addEventListener("DOMContentLoaded", init);

  function init() {
    bindDom();
    const initial = initialRoot();
    state.root = initial.root;
    state.rootExplicit = initial.explicit;
    dom.rootInput.value = state.root;
    dom.controls.addEventListener("submit", onRefreshSubmit);
    dom.autoRefresh.addEventListener("change", updateAutoRefresh);
    renderEmpty();
    bindHistory();
    refreshHistory().then(function () {
      if (state.rootExplicit || state.historyTotal === 0) refreshSnapshot();
      else document.querySelector(".dashboard").hidden = true;
    });
  }

  function bindDom() {
    dom.controls = document.getElementById("console-controls");
    dom.rootInput = document.getElementById("artifact-root");
    dom.refreshButton = document.getElementById("refresh-button");
    dom.autoRefresh = document.getElementById("auto-refresh");
    dom.lastRefresh = document.getElementById("last-refresh");
    dom.banner = document.getElementById("status-banner");
    dom.subtitle = document.getElementById("snapshot-subtitle");
    dom.overviewMeta = document.getElementById("overview-meta");
    dom.runStatus = document.getElementById("run-status");
    dom.overviewGrid = document.getElementById("overview-grid");
    dom.focusStageStatus = document.getElementById("focus-stage-status");
    dom.focusDetails = document.getElementById("focus-details");
    dom.attemptCount = document.getElementById("attempt-count");
    dom.attemptsBody = document.getElementById("attempts-body");
    dom.eventCount = document.getElementById("event-count");
    dom.timelineList = document.getElementById("timeline-list");
    dom.artifactCount = document.getElementById("artifact-count");
    dom.artifactWarnings = document.getElementById("artifact-warnings");
    dom.artifactLinks = document.getElementById("artifact-links");
    dom.configFocus = document.getElementById("config-focus");
    dom.configSummary = document.getElementById("config-summary");
  }

  function initialRoot() {
    const params = new URLSearchParams(window.location.search);
    const queryRoot = (params.get("root") || "").trim();
    if (queryRoot) {
      return { root: queryRoot, explicit: true };
    }
    const storedRoot =
      readStorage(STORAGE_USER_SET_KEY) === "1" ? readStorage(STORAGE_KEY).trim() : "";
    return { root: storedRoot, explicit: Boolean(storedRoot) };
  }

  function onRefreshSubmit(event) {
    event.preventDefault();
    const nextRoot = dom.rootInput.value.trim();
    state.root = nextRoot;
    state.rootExplicit = Boolean(nextRoot);
    dom.rootInput.value = state.root;
    if (state.rootExplicit) {
      writeStorage(STORAGE_KEY, state.root);
      writeStorage(STORAGE_USER_SET_KEY, "1");
    } else {
      removeStorage(STORAGE_KEY);
      removeStorage(STORAGE_USER_SET_KEY);
    }
    updateUrlRoot(state.root);
    refreshSnapshot();
  }

  async function refreshSnapshot() {
    if (state.loading) {
      return;
    }
    const requestedRoot = state.root;
    state.loading = true;
    state.error = null;
    showBanner("loading", "Loading snapshot...");
    dom.refreshButton.disabled = true;

    try {
      const response = await fetch(consoleSnapshotUrl(), {
        headers: { Accept: "application/json" },
        cache: "no-store",
      });
      if (!response.ok) {
        const failure = await response.json();
        throw new Error(failure.error || "Unable to load report (HTTP " + response.status + ")");
      }
      const raw = await response.json();
      if (requestedRoot !== state.root) return;
      state.report = raw;
      state.snapshot = raw.fault ? normalizeSnapshot(raw.fault) : null;
      if (state.snapshot) renderSnapshot(state.snapshot);
      document.querySelector(".dashboard").hidden = !raw.fault;
      renderRunReport(raw);
      state.lastLoadedAt = new Date();
      hideBanner();
    } catch (error) {
      if (requestedRoot !== state.root) return;
      state.error = error;
      showBanner("error", error.message || "Unable to load snapshot");
    } finally {
      state.loading = false;
      dom.refreshButton.disabled = false;
      renderLastRefresh();
      if (requestedRoot !== state.root) refreshSnapshot();
    }
  }

  function consoleSnapshotUrl() {
    if (!state.rootExplicit || !state.root) {
      return "/api/report";
    }
    return "/api/report?root=" + encodeURIComponent(state.root);
  }

  function bindHistory() {
    document.getElementById("history-controls").addEventListener("submit", function (event) {
      event.preventDefault();
      state.historyOffset = 0;
      refreshHistory();
    });
    document.getElementById("history-previous").addEventListener("click", function () {
      state.historyOffset = Math.max(0, state.historyOffset - state.historyLimit);
      refreshHistory();
    });
    document.getElementById("history-next").addEventListener("click", function () {
      state.historyOffset += state.historyLimit;
      refreshHistory();
    });
  }

  async function refreshHistory() {
    const request = ++state.historyRequest;
    const params = new URLSearchParams({ offset: state.historyOffset, limit: state.historyLimit });
    ["kind", "result", "since", "until"].forEach(function (key) {
      const value = document.getElementById("history-" + key).value;
      if (value) params.set(key, value);
    });
    const message = document.getElementById("history-message");
    try {
      const response = await fetch("/api/runs?" + params, { cache: "no-store" });
      const page = await response.json();
      if (request !== state.historyRequest) return;
      if (!response.ok) throw new Error(page.error || "Unable to load history");
      state.historyTotal = page.total;
      if (page.offset > 0 && page.offset >= page.total) {
        state.historyOffset = Math.max(0, Math.ceil(page.total / page.limit) - 1) * page.limit;
        return refreshHistory();
      }
      const body = document.getElementById("history-body");
      body.replaceChildren();
      page.runs.forEach(function (run) {
        const row = document.createElement("tr");
        [run.startedAt, run.id, run.kind, run.target, run.result].forEach(function (value, index) {
          const cell = document.createElement("td");
          if (index === 1) {
            const button = document.createElement("button");
            button.className = "history-select";
            button.type = "button";
            button.textContent = value;
            button.addEventListener("click", function () {
              state.root = run.root;
              state.rootExplicit = true;
              dom.rootInput.value = run.root;
              updateUrlRoot(run.root);
              refreshSnapshot();
            });
            cell.appendChild(button);
          } else cell.textContent = value || "-";
          row.appendChild(cell);
        });
        body.appendChild(row);
      });
      document.getElementById("history-count").textContent = page.total;
      document.getElementById("history-page").textContent = page.total
        ? (page.offset + 1) + "–" + Math.min(page.offset + page.limit, page.total) + " of " + page.total
        : "No runs";
      document.getElementById("history-previous").disabled = page.offset === 0;
      document.getElementById("history-next").disabled = page.offset + page.limit >= page.total;
      message.textContent = page.warnings.join(" ") || (page.total ? "Select a run to view its report." : "No matching recorded runs. Existing fault artifacts can be opened using Artifact root.");
    } catch (error) {
      if (request === state.historyRequest) message.textContent = error.message;
    }
  }

  function renderRunReport(report) {
    const record = report.record || {};
    const summary = report.summary || {};
    document.getElementById("run-report").hidden = false;
    dom.subtitle.textContent = report.root;
    document.getElementById("report-title").textContent = record.id || summary.runId || "Selected run";
    setBadge(document.getElementById("report-result"), report.result, statusClass(report.result));
    const fields = document.getElementById("report-fields");
    fields.replaceChildren();
    const values = [
      ["Type", report.kind], ["Target", record.target], ["Started", record.startedAt],
      ["Finished", record.finishedAt], ["Process exit", record.exitCode],
      ["Runner result", report.artifactResult],
      ["Cleanup", summary.teardownStatus || (report.cleanup && (report.cleanup.status || (report.cleanup.succeeded === true ? "passed" : report.cleanup.succeeded === false ? "failed" : "see details")))],
    ];
    values.forEach(function ([key, value]) {
      if (value == null) return;
      const label = document.createElement("dt");
      const text = document.createElement("dd");
      label.textContent = key;
      text.textContent = value;
      fields.append(label, text);
    });
    document.getElementById("report-warnings").textContent = report.warnings.join(" ");
    ["failure", "cleanup", "summary"].forEach(function (key) {
      document.getElementById("report-" + key + "-section").hidden = !report[key];
      document.getElementById("report-" + key).textContent = report[key] ? JSON.stringify(report[key], null, 2) : "";
    });
    document.getElementById("report-failure-section").open = Boolean(report.failure);
    const artifactUrl = function (path) {
      return "/api/artifact?" + new URLSearchParams({ root: report.artifactRoot, path: path });
    };
    const cases = Array.isArray(summary.caseResults) ? summary.caseResults : [];
    document.getElementById("report-case-section").hidden = cases.length === 0;
    const caseBody = document.getElementById("report-cases");
    caseBody.replaceChildren();
    cases.forEach(function (result) {
      const row = document.createElement("tr");
      [result.caseId, result.variantId, result.outcome, result.cleanupSucceeded === true ? "passed" : result.cleanupSucceeded === false ? "failed" : "unknown", result.failureClassification].forEach(function (value, index) {
        const cell = document.createElement("td");
        if (index === 0 && result.report) {
          const link = document.createElement("a");
          link.textContent = value;
          link.href = artifactUrl(result.report);
          link.target = "_blank";
          link.rel = "noopener";
          cell.appendChild(link);
        } else cell.textContent = value || "-";
        row.appendChild(cell);
      });
      caseBody.appendChild(row);
    });
    const evidence = document.getElementById("report-artifact-links");
    evidence.replaceChildren();
    const paths = (report.kind === "protocol"
      ? [summary.plan, summary.preflight, summary.registry, summary.cleanup, summary.flakyHistory, summary.failureSummary]
      : []).concat(Object.values(summary.artifacts || {}))
      .filter(function (path) { return typeof path === "string" && path.length; });
    Array.from(new Set(paths)).slice(0, MAX_ARTIFACT_LINKS).forEach(function (path) {
      const link = document.createElement("a");
      link.textContent = path;
      link.href = artifactUrl(path);
      link.target = "_blank";
      link.rel = "noopener";
      evidence.appendChild(link);
    });
    const artifacts = document.getElementById("report-artifacts");
    artifacts.href = artifactUrl(".");
  }

  function updateAutoRefresh() {
    if (state.autoTimer) {
      clearInterval(state.autoTimer);
      state.autoTimer = null;
    }
    if (dom.autoRefresh.checked) {
      state.autoTimer = setInterval(function () {
        refreshHistory();
        if (state.report || state.rootExplicit) refreshSnapshot();
      }, AUTO_REFRESH_MS);
    }
  }

  function normalizeSnapshot(raw) {
    const summary = firstObject(
      readAny(raw, ["suiteSummary", "summary", "runSummary"]),
      isSuiteSummary(raw) ? raw : null,
    );
    const plan = firstObject(
      readAny(raw, ["suitePlan", "plan"]),
      isSuitePlan(raw) ? raw : null,
    );
    const rawAttempts = asArray(readField(raw, "attempts"));
    const summaryAttempts = asArray(readField(summary, "attempts"));
    const attempts = rawAttempts.length ? rawAttempts : summaryAttempts;
    const failureSummary = firstObject(
      readAny(raw, ["failureSummary", "currentFailure", "failure"]),
      firstFailureSummary(attempts),
    );
    const summaryFailures = asArray(readField(summary, "failures"));
    const failures = summaryFailures.length ? summaryFailures : asArray(readField(raw, "failures"));
    const runnerFailures = asArray(readField(raw, "runnerFailures"));
    const health = asArray(readField(raw, "health"));
    const events = normalizeEvents(
      readAny(raw, ["events", "timeline", "eventTimeline"]),
    )
      .concat(flattenAttemptEvents(attempts))
      .concat(runnerFailureEvents(runnerFailures))
      .concat(healthEvents(health))
      .sort(compareEvents);
    const artifactData = collectArtifactData(raw, summary, plan, failureSummary, attempts);
    return {
      raw,
      root: readAny(raw, ["artifactRoot", "root"]) || state.root,
      summary,
      plan,
      attempts,
      failures,
      runnerFailures,
      health,
      failureSummary,
      events,
      artifacts: artifactData.links,
      warnings: artifactData.warnings,
      selectedAttempt: selectAttempt(attempts),
    };
  }

  function isSuiteSummary(value) {
    return Boolean(
      value &&
        typeof value === "object" &&
        (readField(value, "runId") || readField(value, "suite")) &&
        Array.isArray(value.attempts),
    );
  }

  function isSuitePlan(value) {
    return Boolean(
      value &&
        typeof value === "object" &&
        value.kind === "FaultSuitePlan" &&
        Array.isArray(value.attempts),
    );
  }

  function renderSnapshot(snapshot) {
    if (!snapshot) {
      renderEmpty();
      return;
    }
    renderOverview(snapshot);
    renderFocus(snapshot);
    renderAttempts(snapshot);
    renderTimeline(snapshot.events);
    renderArtifacts(snapshot);
    renderConfig(snapshot);
  }

  function renderEmpty() {
    dom.subtitle.textContent = state.root || "Server default artifact root";
    dom.overviewMeta.textContent = "Waiting for snapshot";
    setBadge(dom.runStatus, "unknown", "neutral");
    renderMetrics([
      ["Suite", "-"],
      ["Run ID", "-"],
      ["Started", "-"],
      ["Elapsed", "-"],
      ["Attempts", "0"],
      ["Failures", "0"],
      ["Stop policy", "-"],
      ["Disruptions", "-"],
    ]);
    setBadge(dom.focusStageStatus, "unknown", "neutral");
    dom.focusDetails.innerHTML = emptyState("No stage data loaded.");
    dom.attemptCount.textContent = "0";
    dom.attemptsBody.innerHTML = tableEmptyRow("No attempts loaded.");
    dom.eventCount.textContent = "0";
    dom.timelineList.innerHTML = emptyTimeline("No events loaded.");
    dom.artifactCount.textContent = "0";
    dom.artifactWarnings.innerHTML = "";
    dom.artifactLinks.innerHTML = emptyState("No artifact links loaded.");
    dom.configFocus.textContent = "none";
    dom.configSummary.innerHTML = emptyState("No config data loaded.");
    renderLastRefresh();
  }

  function renderOverview(snapshot) {
    const summary = snapshot.summary || {};
    const attempts = snapshot.attempts;
    const failures = snapshot.failures;
    const runnerFailures = snapshot.runnerFailures || [];
    const health = healthOverview(snapshot.health || []);
    const suite = readField(summary, "suite") || readField(snapshot.plan, "suite") || "-";
    const runId =
      readField(summary, "runId") ||
      readField(snapshot.plan, "runId") ||
      "-";
    const status = readField(summary, "status") || readField(snapshot.raw, "status") || "unknown";
    const started = readField(summary, "startedAtMs");
    const ended = readField(summary, "endedAtMs");
    const elapsed =
      readField(summary, "elapsedSeconds") ||
      elapsedSeconds(started, ended);
    const stopOnFirst =
      readField(summary, "stopOnFirstFailure") ??
      readField(snapshot.plan && snapshot.plan.budgets, "stopOnFirstFailure");
    const continueOn =
      readField(summary, "continueOnSeverities") ||
      readField(snapshot.plan && snapshot.plan.budgets, "continueOnSeverities");
    const disruptions = readField(summary, "totalClientDisruptions");

    dom.subtitle.textContent = snapshot.root || "Read-only fault test artifacts";
    dom.overviewMeta.textContent = "suite " + suite + " / run " + runId;
    setBadge(dom.runStatus, status, statusClass(status));
    renderMetrics([
      ["Suite", suite],
      ["Run ID", runId],
      ["Started", formatTime(started)],
      ["Elapsed", formatDuration(elapsed)],
      ["Attempts", attempts.length + " total"],
      ["Failures", failures.length + " recorded"],
      ["Runner failures", runnerFailures.length + " recorded"],
      ["Health", formatHealthOverview(health)],
      ["Stop policy", formatStopPolicy(stopOnFirst, continueOn)],
      ["Disruptions", valueOrDash(disruptions)],
    ]);
  }

  function renderMetrics(items) {
    dom.overviewGrid.innerHTML = items
      .map(function ([label, value]) {
        return (
          '<div class="metric"><span>' +
          escapeHtml(label) +
          "</span><strong>" +
          escapeHtml(String(valueOrDash(value))) +
          "</strong></div>"
        );
      })
      .join("");
  }

  function renderFocus(snapshot) {
    const runnerFailure = primaryRunnerFailure(snapshot.runnerFailures || []);
    const healthSample = primaryHealthSample(snapshot.health || []);
    const runnerIssue = statusClass(runnerFailureStatus(runnerFailure)) === "failed";
    const healthIssue = statusClass(healthSampleStatus(readField(healthSample, "sample"))) === "failed";
    const failure =
      primaryFailure(snapshot) ||
      snapshot.failureSummary ||
      (runnerIssue ? runnerFailure : null) ||
      (healthIssue ? healthSample : null) ||
      null;
    const failureSummary = snapshot.failureSummary || {};
    const latest = latestEvent(snapshot.events);
    const attempt = snapshot.selectedAttempt;
    const status =
      readField(failure, "severity") ||
      (runnerIssue ? runnerFailureStatus(runnerFailure) : "") ||
      (healthIssue ? healthSampleStatus(readField(healthSample, "sample")) : "") ||
      readField(attempt, "status") ||
      readField(latest, "status") ||
      "unknown";
    const stage =
      readField(snapshot.raw, "currentStage") ||
      readField(failure, "stage") ||
      readField(failureSummary, "stage") ||
      (healthIssue ? healthSampleStage(readField(healthSample, "sample")) : "") ||
      readField(latest, "stage") ||
      (attempt ? "attempt " + attemptNumber(attempt) : "-");
    const reason =
      readAny(failure, ["reason", "message", "error"]) ||
      readAny(failureSummary, ["message", "reason", "error"]) ||
      (runnerIssue ? runnerFailureMessage(runnerFailure) : "") ||
      (healthIssue ? healthSampleFocusText(healthSample) : "") ||
      readField(attempt, "error") ||
      readField(latest, "message") ||
      "-";
    const severity =
      readField(failure, "severity") ||
      readField(failureSummary, "severity") ||
      (runnerIssue ? runnerFailureSeverity(runnerFailure) : "") ||
      (healthIssue ? healthSampleSeverity(readField(healthSample, "sample")) : "") ||
      readField(attempt, "severity");
    const classification =
      readField(failure, "classification") ||
      readField(failureSummary, "classification") ||
      (runnerIssue ? runnerFailureClassification(runnerFailure) : "") ||
      (healthIssue ? healthSampleClassification(readField(healthSample, "sample")) : "") ||
      readField(attempt, "classification");
    const evidence =
      readField(failure, "evidenceClassifications") ||
      readField(failureSummary, "evidenceClassifications") ||
      readField(attempt, "evidenceClassifications");

    setBadge(dom.focusStageStatus, status, severityClass(status));
    dom.focusDetails.innerHTML =
      '<dl class="kv-grid">' +
      kv("Stage", stage) +
      kv("Scenario", readField(failure, "scenario") || readField(attempt, "scenario") || "-") +
      kvHtml("Severity", chipValue(severity, severityClass(severity))) +
      kvHtml("Classification", chipValue(classification, severityClass(severity))) +
      kv("Reason", reason) +
      kv("Runner", runnerFailure ? runnerFailureMessage(runnerFailure) : "-") +
      kv("Health", healthSample ? healthSampleFocusText(healthSample) : "-") +
      kvHtml("Evidence", chipList(evidence)) +
      "</dl>";
  }

  function renderAttempts(snapshot) {
    const attempts = snapshot.attempts;
    dom.attemptCount.textContent = String(attempts.length);
    if (!attempts.length) {
      dom.attemptsBody.innerHTML = tableEmptyRow("No attempts in snapshot.");
      return;
    }
    dom.attemptsBody.innerHTML = attempts
      .map(function (attempt) {
        const status = readField(attempt, "status") || "unknown";
        const severity = readField(attempt, "severity");
        const classification = readField(attempt, "classification");
        const artifacts = readAny(attempt, ["artifactsDir", "artifactDir"]);
        const started = readField(attempt, "startedAtMs");
        const ended = readField(attempt, "endedAtMs");
        const duration = elapsedSeconds(started, ended);
        return (
          "<tr>" +
          td(escapeHtml(attemptNumber(attempt))) +
          td(codeText(readField(attempt, "scenario") || "-")) +
          td(escapeHtml(valueOrDash(readField(attempt, "repetition")))) +
          td(badgeHtml(status, statusClass(status))) +
          td(escapeHtml(formatDuration(duration))) +
          td(chipValue(severity, severityClass(severity))) +
          td(chipValue(classification, severityClass(severity))) +
          td(artifactCell(artifacts, "attempt artifacts")) +
          td(escapeHtml(valueOrDash(attemptReason(attempt)))) +
          "</tr>"
        );
      })
      .join("");
  }

  function renderTimeline(events) {
    const visible = events.slice(-MAX_TIMELINE_EVENTS);
    dom.eventCount.textContent = String(events.length);
    if (!visible.length) {
      dom.timelineList.innerHTML = emptyTimeline("No events in snapshot.");
      return;
    }
    dom.timelineList.innerHTML = visible
      .map(function (event) {
        const status = readField(event, "status") || "observed";
        const details = readField(event, "details");
        return (
          '<li class="timeline-item">' +
          '<time class="timeline-time">' +
          escapeHtml(formatTime(readAny(event, ["atMs", "timeMs"]))) +
          "</time>" +
          '<div class="timeline-main">' +
          '<div class="timeline-title">' +
          badgeHtml(status, statusClass(status)) +
          "<strong>" +
          escapeHtml(readField(event, "stage") || "-") +
          "</strong>" +
          "</div>" +
          '<p class="timeline-message">' +
          escapeHtml(readField(event, "message") || "") +
          "</p>" +
          renderEventDetails(details) +
          "</div>" +
          "</li>"
        );
      })
      .join("");
  }

  function renderArtifacts(snapshot) {
    const warnings = snapshot.warnings;
    const links = snapshot.artifacts.slice(0, MAX_ARTIFACT_LINKS);
    dom.artifactCount.textContent = String(snapshot.artifacts.length);
    dom.artifactWarnings.innerHTML = warnings.length
      ? warnings
          .map(function (warning) {
            return renderWarning(warning);
          })
          .join("")
      : "";

    if (!links.length) {
      dom.artifactLinks.innerHTML = emptyState("No artifact links in snapshot.");
      return;
    }
    const overflow =
      snapshot.artifacts.length > MAX_ARTIFACT_LINKS
        ? '<div class="muted">+' +
          (snapshot.artifacts.length - MAX_ARTIFACT_LINKS) +
          " more artifacts</div>"
        : "";
    dom.artifactLinks.innerHTML =
      links
        .map(function (artifact) {
          const label = readAny(artifact, ["label", "name"]) || "artifact";
          const path = artifactDisplayPath(artifact);
          const href = artifactLinkHref(artifact);
          const downloadHref = artifactDownloadHrefFor(artifact);
          const target = href
            ? '<span class="artifact-actions"><a class="mono" href="' +
              escapeAttr(href) +
              '" target="_blank" rel="noreferrer">Open</a>' +
              (downloadHref
                ? '<a class="mono artifact-download" href="' +
                  escapeAttr(downloadHref) +
                  '" download>Download</a>'
                : "") +
              '<code class="mono">' +
              escapeHtml(path || href) +
              "</code></span>"
            : '<code class="mono">' + escapeHtml(path || "-") + "</code>";
          return (
            '<div class="artifact-link"><span>' +
            escapeHtml(label) +
            "</span>" +
            target +
            "</div>"
          );
        })
        .join("") + overflow;
  }

  function renderConfig(snapshot) {
    const attempt = snapshot.selectedAttempt;
    const planAttempt = findPlanAttempt(snapshot.plan, attempt);
    const rawPlan = planRaw(snapshot.plan);
    const config = firstObject(
      planAttempt,
      readAny(snapshot.raw, ["config", "currentConfig"]),
    );
    const workload =
      readField(config, "workload") ||
      readField(snapshot.raw, "workload") ||
      readField(snapshot.failureSummary, "workload");
    const faults =
      asArray(readField(config, "faults")).length
        ? asArray(readField(config, "faults"))
        : asArray(readField(snapshot.raw, "faults"));
    const budgets = firstObject(
      readAny(config, ["budget", "budgets"]),
      readField(rawPlan, "budgets"),
      readField(snapshot.plan, "budgets"),
      readField(snapshot.summary, "budgets"),
      snapshot.summary,
    );

    dom.configFocus.textContent = planAttempt
      ? "attempt " + attemptNumber(planAttempt)
      : attempt
        ? "attempt " + attemptNumber(attempt)
        : "suite";
    if (!config && !workload && !faults.length && !budgets) {
      dom.configSummary.innerHTML = emptyState("No workload, fault, or budget config in snapshot.");
      return;
    }

    dom.configSummary.innerHTML =
      configSection("Workload", workloadKv(workload)) +
      configSection("Faults", faultList(faults)) +
      configSection("Budget", budgetKv(budgets));
  }

  function workloadKv(workload) {
    if (!workload || typeof workload !== "object") {
      return emptyState("No workload config.");
    }
    const operationMix =
      readField(workload, "operationMix") ||
      readField(workload, "operationWeights");
    const payload =
      readField(workload, "payloadDistribution") ||
      readField(workload, "payload");
    return (
      '<dl class="kv-grid">' +
      kv("Profile", readAny(workload, ["profile", "workloadProfile"]) || "-") +
      kv("Mode", readField(workload, "mode") || "-") +
      kv("Objects", readAny(workload, ["objects", "objectCount"])) +
      kv("Concurrency", readField(workload, "concurrency")) +
      kv("Prefill", readField(workload, "prefillConcurrency")) +
      kv("Request timeout", secondsValue(readField(workload, "requestTimeoutSeconds"))) +
      kvHtml("Operation mix", compactJson(operationMix)) +
      kvHtml("Payload", compactJson(payload)) +
      kv("Seed", readField(workload, "seed")) +
      "</dl>"
    );
  }

  function faultList(faults) {
    if (!faults.length) {
      return emptyState("No fault config.");
    }
    return (
      '<div class="fault-list">' +
      faults
        .map(function (fault) {
          const target = readField(fault, "target");
          const selection = readField(fault, "selection");
          const duration = secondsValue(
            readField(fault, "faultDurationSeconds"),
          );
          const params = readAny(fault, ["parameters", "params"]);
          return (
            '<div class="fault-row">' +
            "<strong>" +
            escapeHtml(readField(fault, "name") || readField(fault, "kind") || "fault") +
            "</strong>" +
            "<span>" +
            escapeHtml(
              [
                readField(fault, "kind"),
                readField(fault, "backend"),
                duration ? "duration " + duration : null,
              ]
                .filter(Boolean)
                .join(" / "),
            ) +
            "</span>" +
            "<span>" +
            escapeHtml(
              [
                target ? "target " + targetSummary(target) : null,
                selection ? "selection " + targetSummary(selection) : null,
                params ? "params " + compactText(params) : null,
              ]
                .filter(Boolean)
                .join(" / "),
            ) +
            "</span>" +
            "</div>"
          );
        })
        .join("") +
      "</div>"
    );
  }

  function budgetKv(budgets) {
    if (!budgets || typeof budgets !== "object") {
      return emptyState("No budget config.");
    }
    return (
      '<dl class="kv-grid">' +
      kv("Stop on first", formatBool(readField(budgets, "stopOnFirstFailure"))) +
      kvHtml("Continue on", chipList(readField(budgets, "continueOnSeverities"))) +
      kv("Fault duration", secondsValue(readField(budgets, "faultDurationSeconds"))) +
      kv("Recovery timeout", secondsValue(readField(budgets, "recoveryTimeoutSeconds"))) +
      kv("Max duration", secondsValue(readField(budgets, "maxDurationSeconds"))) +
      kv("Max disruptions", readField(budgets, "maxClientDisruptions")) +
      kv("Total disruptions", readField(budgets, "totalClientDisruptions")) +
      kv("Cluster timeout", secondsValue(readField(budgets, "clusterTimeoutSeconds"))) +
      kv("Recovery stable", secondsValue(readField(budgets, "recoveryStableWindowSeconds"))) +
      kv("Reread window", secondsValue(readField(budgets, "recoveryStabilityRereadSeconds"))) +
      kv("Minimum required", secondsValue(readField(budgets, "minimumRequiredSeconds"))) +
      kv("Remaining before", secondsValue(readField(budgets, "remainingBeforeSeconds"))) +
      kv("Remaining after minimum", secondsValue(readField(budgets, "remainingAfterMinimumSeconds"))) +
      "</dl>"
    );
  }

  function collectArtifactData(raw, summary, plan, failureSummary, attempts) {
    const links = [];
    const warnings = [];
    const directArtifacts = readAny(raw, ["artifacts", "artifactLinks"]);
    const artifactLinks = Array.isArray(directArtifacts)
      ? directArtifacts
      : asArray(readAny(directArtifacts, ["links", "items"]));

    artifactLinks.forEach(function (item) {
      links.push(normalizeArtifact(item));
    });

    collectWarnings(warnings, readAny(raw, ["warnings", "artifactWarnings"]));
    collectWarnings(warnings, readField(directArtifacts, "warnings"));

    if (plan) {
      addArtifact(links, "suite plan", readField(plan, "path") || "suite-plan.json");
    }
    if (summary) {
      addArtifact(links, "suite summary", readField(summary, "path") || "suite-summary.json");
    }
    asArray(readField(raw, "runnerFailures")).forEach(function (failure) {
      addArtifact(links, "runner failure", readField(failure, "path"));
      const logPath = readAny(failure, ["testLog", "suiteLog"]);
      if (logPath) {
        addArtifact(links, "runner log", logPath);
      }
    });
    asArray(readField(raw, "health")).forEach(function (artifact) {
      addArtifact(links, "health watch", readField(artifact, "path"));
    });
    asArray(readField(raw, "exitCodes")).forEach(function (artifact) {
      addArtifact(links, readField(artifact, "artifact") || "exit code", readField(artifact, "path"));
    });
    asArray(readField(summary, "failures")).forEach(function (failure) {
      const failureSummaryPath = artifactPathFrom(readField(failure, "failureSummary"));
      if (failureSummaryPath) {
        addArtifact(links, "failure summary", failureSummaryPath);
      }
      addPrimaryEvidenceArtifacts(links, failure, failureSummaryPath);
      const dir = readField(failure, "attemptArtifactsDir");
      if (dir) {
        addArtifact(links, "failed attempt", dir);
      }
    });
    attempts.forEach(function (attempt) {
      const dir = readAny(attempt, ["artifactsDir", "artifactDir"]);
      if (dir) {
        addArtifact(links, "attempt " + attemptNumber(attempt), dir);
      }
      asArray(readField(attempt, "cases")).forEach(function (testCase) {
        const caseDir = readField(testCase, "artifactDir");
        addArtifact(links, "case " + (readField(testCase, "caseName") || "artifact"), caseDir);
        addArtifact(links, "events", readField(testCase, "eventArtifact"));
        const caseFailure = readField(testCase, "failureSummary");
        if (caseFailure) {
          addArtifact(
            links,
            "failure summary",
            artifactPathFrom(caseFailure) || joinArtifactPath(caseDir, "failure-summary.json"),
          );
          addPrimaryEvidenceArtifacts(links, caseFailure, artifactPathFrom(caseFailure));
        }
      });
    });
    if (failureSummary) {
      addArtifact(links, "failure summary", artifactPathFrom(failureSummary));
      addPrimaryEvidenceArtifacts(links, failureSummary, artifactPathFrom(failureSummary));
    }

    return {
      links: uniqueArtifacts(links.filter(Boolean)),
      warnings: uniqueWarnings(warnings),
    };
  }

  function normalizeArtifact(item) {
    if (typeof item === "string") {
      const path = normalizeArtifactPath(item);
      return { label: basename(path), path };
    }
    if (!item || typeof item !== "object") {
      return null;
    }
    const path = artifactPathFrom(item);
    return {
      label: readAny(item, ["label", "title", "name"]) || basename(path || ""),
      path,
      href: readField(item, "href"),
      url: readField(item, "url"),
    };
  }

  function addArtifact(links, label, path) {
    if (path) {
      links.push({ label, path: normalizeArtifactPath(path) });
    }
  }

  function addPrimaryEvidenceArtifacts(links, source, summaryPath) {
    const normalizedSummaryPath = normalizeArtifactPath(summaryPath || artifactPathFrom(source));
    const resolvedArtifacts = readAny(source, ["primaryEvidenceArtifacts", "primary_evidence_artifacts"]);
    if (resolvedArtifacts !== undefined) {
      asArray(resolvedArtifacts).forEach(function (path) {
        addPrimaryEvidenceArtifact(links, path, normalizedSummaryPath);
      });
      return;
    }
    asArray(readAny(source, ["primaryEvidenceRefs", "primary_evidence_refs"])).forEach(
      function (path) {
        const normalized = normalizeArtifactPath(path);
        const resolved = normalized.includes("/")
          ? normalized
          : joinArtifactPath(dirnameArtifactPath(normalizedSummaryPath), normalized);
        addPrimaryEvidenceArtifact(links, resolved, normalizedSummaryPath);
      },
    );
  }

  function addPrimaryEvidenceArtifact(links, path, summaryPath) {
    const normalized = normalizeArtifactPath(path);
    if (normalized && normalized !== summaryPath) {
      addArtifact(links, "primary evidence", normalized);
    }
  }

  function artifactPathFrom(value) {
    if (typeof value === "string") {
      return normalizeArtifactPath(value);
    }
    if (!value || typeof value !== "object") {
      return "";
    }
    const path = readAny(value, ["path", "file", "artifact", "name"]);
    return path ? normalizeArtifactPath(path) : "";
  }

  function artifactDisplayPath(artifact) {
    return (
      readField(artifact, "path") ||
      readField(artifact, "href") ||
      readField(artifact, "url") ||
      ""
    );
  }

  function artifactLinkHref(artifact) {
    const direct = readAny(artifact, ["href", "url"]);
    if (isExternalUrl(direct)) {
      return direct;
    }
    return artifactHref(readField(artifact, "path") || direct);
  }

  function joinArtifactPath(base, leaf) {
    if (!base || !leaf) {
      return "";
    }
    return normalizeArtifactPath(String(base).replace(/\/+$/, "") + "/" + leaf);
  }

  function dirnameArtifactPath(path) {
    const normalized = normalizeArtifactPath(path || "");
    const index = normalized.lastIndexOf("/");
    return index >= 0 ? normalized.slice(0, index) : "";
  }

  function uniqueArtifacts(links) {
    const seen = new Set();
    return links.filter(function (link) {
      const key = [link.label, link.path, link.href, link.url].join("|");
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  function normalizeEvents(value) {
    if (!value) {
      return [];
    }
    if (Array.isArray(value)) {
      return value.filter(Boolean).sort(compareEvents);
    }
    if (typeof value === "string") {
      return value
        .split(/\r?\n/)
        .map(function (line) {
          const trimmed = line.trim();
          if (!trimmed) {
            return null;
          }
          try {
            return JSON.parse(trimmed);
          } catch (_) {
            return { stage: "log", status: "observed", message: trimmed };
          }
        })
        .filter(Boolean)
        .sort(compareEvents);
    }
    if (typeof value === "object") {
      return asArray(pick(value, ["items", "events"])).sort(compareEvents);
    }
    return [];
  }

  function flattenAttemptEvents(attempts) {
    const events = [];
    attempts.forEach(function (attempt) {
      asArray(readField(attempt, "cases")).forEach(function (testCase) {
        const caseEvents = asArray(readField(testCase, "events"));
        caseEvents.forEach(function (event) {
          events.push(event);
        });
      });
    });
    return events;
  }

  function runnerFailureEvents(runnerFailures) {
    return runnerFailures.map(function (failure) {
      return {
        stage: readField(failure, "stage") || "runner",
        status: runnerFailureStatus(failure),
        message: runnerFailureMessage(failure),
        details: failure,
      };
    });
  }

  function healthEvents(healthArtifacts) {
    const events = [];
    healthArtifacts.forEach(function (artifact) {
      asArray(readField(artifact, "samples")).forEach(function (sample) {
        events.push({
          atMs: healthSampleAtMs(sample),
          stage: healthSampleStage(sample),
          status: healthSampleStatus(sample),
          message: healthSampleMessage(sample),
          details: {
            artifact: readAny(artifact, ["path", "artifact"]) || "health-watch",
            sample,
          },
        });
      });
    });
    return events;
  }

  function firstFailureSummary(attempts) {
    for (const attempt of attempts) {
      for (const testCase of asArray(readField(attempt, "cases"))) {
        const failure = readField(testCase, "failureSummary");
        if (failure && typeof failure === "object") {
          return failure;
        }
      }
    }
    return null;
  }

  function compareEvents(left, right) {
    const leftTime = Number(readAny(left, ["atMs", "timeMs"]) || 0);
    const rightTime = Number(readAny(right, ["atMs", "timeMs"]) || 0);
    return leftTime - rightTime;
  }

  function selectAttempt(attempts) {
    return (
      attempts.find(function (attempt) {
        return readField(attempt, "status") === "running";
      }) ||
      attempts.find(function (attempt) {
        return readField(attempt, "status") === "failed";
      }) ||
      attempts[attempts.length - 1] ||
      null
    );
  }

  function findPlanAttempt(plan, attempt) {
    const planned = planAttempts(plan);
    if (!attempt || !planned.length) {
      return planned[planned.length - 1] || null;
    }
    const index = readField(attempt, "index");
    const scenario = readField(attempt, "scenario");
    const repetition = readField(attempt, "repetition");
    return (
      planned.find(function (item) {
        return readField(item, "index") === index;
      }) ||
      planned.find(function (item) {
        return (
          readField(item, "scenario") === scenario &&
          readField(item, "repetition") === repetition
        );
      }) ||
      planned[planned.length - 1] ||
      null
    );
  }

  function planAttempts(plan) {
    const raw = planRaw(plan);
    const rawAttempts = asArray(readField(raw, "attempts"));
    return rawAttempts.length ? rawAttempts : asArray(readField(plan, "attempts"));
  }

  function planRaw(plan) {
    return firstObject(readField(plan, "raw"), isSuitePlan(plan) ? plan : null);
  }

  function primaryFailure(snapshot) {
    const failures = snapshot.failures;
    const stopReason = readField(snapshot.summary, "stopReason");
    const failureIndex = readField(stopReason, "failureIndex");
    if (failureIndex !== undefined && failureIndex !== null) {
      const stopped = failures.find(function (failure) {
        return readField(failure, "index") === failureIndex;
      });
      if (stopped || failures[failureIndex]) {
        return stopped || failures[failureIndex];
      }
    }
    return (
      failures.find(function (failure) {
        return readField(failure, "stoppedSuite");
      }) ||
      failures[0] ||
      null
    );
  }

  function primaryRunnerFailure(runnerFailures) {
    return (
      runnerFailures.find(function (failure) {
        return statusClass(readField(failure, "status")) === "failed";
      }) ||
      runnerFailures.find(function (failure) {
        return (
          truthy(readField(failure, "healthGuardFailed")) ||
          truthy(readField(failure, "suiteBudgetFailed"))
        );
      }) ||
      runnerFailures.find(function (failure) {
        const exitCode = Number(readField(failure, "exitCode"));
        return Number.isFinite(exitCode) && exitCode !== 0;
      }) ||
      runnerFailures[0] ||
      null
    );
  }

  function primaryHealthSample(healthArtifacts) {
    let latest = null;
    let latestIssue = null;
    healthArtifacts.forEach(function (artifact) {
      asArray(readField(artifact, "samples")).forEach(function (sample) {
        const entry = { artifact, sample };
        latest = newerHealthEntry(latest, entry);
        if (healthSampleStatus(sample) === "failed") {
          latestIssue = newerHealthEntry(latestIssue, entry);
        }
      });
    });
    return latestIssue || latest;
  }

  function newerHealthEntry(current, next) {
    if (!current) {
      return next;
    }
    return healthSampleAtMs(next.sample) >= healthSampleAtMs(current.sample) ? next : current;
  }

  function runnerFailureStatus(failure) {
    if (!failure) {
      return "";
    }
    const status = readField(failure, "status");
    if (status) {
      return status;
    }
    const exitCode = Number(readField(failure, "exitCode"));
    if (
      truthy(readField(failure, "healthGuardFailed")) ||
      truthy(readField(failure, "suiteBudgetFailed")) ||
      (Number.isFinite(exitCode) && exitCode !== 0)
    ) {
      return "failed";
    }
    return "observed";
  }

  function runnerFailureSeverity(failure) {
    if (!failure) {
      return "";
    }
    const severity = readField(failure, "severity");
    if (severity) {
      return severity;
    }
    if (
      truthy(readField(failure, "healthGuardFailed")) ||
      truthy(readField(failure, "suiteBudgetFailed"))
    ) {
      return "infra";
    }
    return runnerFailureStatus(failure);
  }

  function runnerFailureClassification(failure) {
    if (!failure) {
      return "";
    }
    const classification = readField(failure, "classification");
    if (classification) {
      return classification;
    }
    if (truthy(readField(failure, "healthGuardFailed"))) {
      return "health_guard_failed";
    }
    if (truthy(readField(failure, "suiteBudgetFailed"))) {
      return "suite_budget_failed";
    }
    return "runner_failure";
  }

  function runnerFailureMessage(failure) {
    if (!failure) {
      return "";
    }
    const message = readAny(failure, ["message", "reason", "error"]);
    if (message) {
      return message;
    }
    const scope =
      readField(failure, "suite") || readField(failure, "scenario") || readField(failure, "path");
    const exitCode = readField(failure, "exitCode");
    const flags = [];
    if (truthy(readField(failure, "healthGuardFailed"))) {
      flags.push("health_guard_failed");
    }
    if (truthy(readField(failure, "suiteBudgetFailed"))) {
      flags.push("suite_budget_failed");
    }
    if (truthy(readField(failure, "rustFailureSummaryPresent"))) {
      flags.push("rust_failure_summary_present");
    }
    if (truthy(readField(failure, "suiteSummaryPresent"))) {
      flags.push("suite_summary_present");
    }
    return [
      scope ? "scope " + scope : "runner failure",
      exitCode !== undefined && exitCode !== null ? "exit " + exitCode : null,
      flags.length ? flags.join(", ") : null,
    ]
      .filter(Boolean)
      .join(" / ");
  }

  function healthOverview(healthArtifacts) {
    const summary = {
      samples: 0,
      unsafe: 0,
      budgetFailed: 0,
    };
    healthArtifacts.forEach(function (artifact) {
      asArray(readField(artifact, "samples")).forEach(function (sample) {
        summary.samples += 1;
        if (falsy(readField(sample, "safe"))) {
          summary.unsafe += 1;
        }
        if (falsy(readField(sample, "budget"))) {
          summary.budgetFailed += 1;
        }
      });
    });
    return summary;
  }

  function formatHealthOverview(summary) {
    if (!summary.samples) {
      return "0 samples";
    }
    const parts = [summary.samples + " samples"];
    if (summary.unsafe) {
      parts.push(summary.unsafe + " unsafe");
    }
    if (summary.budgetFailed) {
      parts.push(summary.budgetFailed + " budget failed");
    }
    return parts.join(", ");
  }

  function healthSampleAtMs(sample) {
    const direct = Number(readField(sample, "atMs"));
    if (Number.isFinite(direct) && direct > 0) {
      return direct;
    }
    const raw = readField(sample, "raw");
    const rawMs = Number(readField(raw, "atMs"));
    if (Number.isFinite(rawMs) && rawMs > 0) {
      return rawMs;
    }
    const at = readField(sample, "at") || readAny(raw, ["at", "time", "timestamp"]);
    const parsed = Date.parse(at);
    return Number.isFinite(parsed) ? parsed : 0;
  }

  function healthSampleStage(sample) {
    if (!sample) {
      return "";
    }
    const stage = readField(sample, "stage");
    if (stage) {
      return stage;
    }
    const raw = readField(sample, "raw");
    const scope = readField(raw, "scope");
    return scope ? "health " + scope : "health";
  }

  function healthSampleStatus(sample) {
    if (!sample) {
      return "";
    }
    const status = readField(sample, "status");
    if (status) {
      return status;
    }
    if (falsy(readField(sample, "safe")) || falsy(readField(sample, "budget"))) {
      return "failed";
    }
    if (truthy(readField(sample, "safe")) || truthy(readField(sample, "budget"))) {
      return "succeeded";
    }
    return "observed";
  }

  function healthSampleSeverity(sample) {
    const severity = readField(sample, "severity");
    if (severity) {
      return severity;
    }
    return healthSampleStatus(sample) === "failed" ? "infra" : "";
  }

  function healthSampleClassification(sample) {
    if (!sample) {
      return "";
    }
    const classification = readField(sample, "classification");
    if (classification) {
      return classification;
    }
    if (falsy(readField(sample, "budget"))) {
      return "suite_budget_failed";
    }
    if (falsy(readField(sample, "safe"))) {
      return "health_guard_failed";
    }
    return "";
  }

  function healthSampleMessage(sample) {
    if (!sample) {
      return "";
    }
    const direct = readAny(sample, ["message", "reason", "error"]);
    if (direct) {
      return direct;
    }
    const raw = readField(sample, "raw");
    const message = readAny(raw, ["message", "reason"]);
    if (message) {
      return message;
    }
    const classification = healthSampleClassification(sample);
    if (classification) {
      return classification;
    }
    return "health sample";
  }

  function healthSampleFocusText(entry) {
    if (!entry) {
      return "";
    }
    const path = readAny(entry.artifact, ["path", "artifact"]);
    return [healthSampleMessage(entry.sample), path].filter(Boolean).join(" / ");
  }

  function latestEvent(events) {
    return events[events.length - 1] || null;
  }

  function kv(label, value) {
    return kvBase(label, value === undefined || value === null || value === ""
      ? "-"
      : escapeHtml(String(value)));
  }

  function kvHtml(label, value) {
    return kvBase(label, value === undefined || value === null || value === "" ? "-" : value);
  }

  function kvBase(label, value) {
    return (
      "<dt>" +
      escapeHtml(label) +
      "</dt><dd>" +
      value +
      "</dd>"
    );
  }

  function td(value) {
    return "<td>" + (value === undefined || value === null || value === "" ? "-" : value) + "</td>";
  }

  function configSection(title, content) {
    return (
      '<section class="config-section"><h3>' +
      escapeHtml(title) +
      "</h3>" +
      content +
      "</section>"
    );
  }

  function badgeHtml(value, className) {
    return (
      '<span class="badge ' +
      escapeAttr(className || "neutral") +
      '">' +
      escapeHtml(valueOrDash(value)) +
      "</span>"
    );
  }

  function chipValue(value, className) {
    if (value === undefined || value === null || value === "") {
      return '<span class="muted">-</span>';
    }
    return (
      '<span class="chip ' +
      escapeAttr(className || "neutral") +
      '">' +
      escapeHtml(String(value)) +
      "</span>"
    );
  }

  function chipList(value) {
    const values = asArray(value);
    if (!values.length) {
      return '<span class="muted">-</span>';
    }
    return (
      '<span class="chip-row">' +
      values
        .map(function (item) {
          return chipValue(item, severityClass(item));
        })
        .join("") +
      "</span>"
    );
  }

  function artifactCell(path, label) {
    if (!path) {
      return '<span class="muted">-</span>';
    }
    const href = artifactHref(path);
    if (!href) {
      return '<code class="mono">' + escapeHtml(path) + "</code>";
    }
    const downloadHref = artifactDownloadHref(path);
    return (
      '<span class="artifact-actions compact">' +
      '<a class="mono" href="' +
      escapeAttr(href) +
      '" target="_blank" rel="noreferrer">' +
      escapeHtml(label || path) +
      "</a>" +
      (downloadHref
        ? '<a class="mono artifact-download" href="' +
          escapeAttr(downloadHref) +
          '" download>Download</a>'
        : "") +
      "</span>"
    );
  }

  function artifactHref(path) {
    if (!path || typeof path !== "string") {
      return "";
    }
    if (isExternalUrl(path)) {
      return path;
    }
    const artifactPath = normalizeArtifactPath(path);
    if (!artifactPath) {
      return "";
    }
    const effectiveRoot =
      (state.snapshot && state.snapshot.root) ||
      (state.rootExplicit ? state.root : "");
    const rootQuery = effectiveRoot ? "root=" + encodeURIComponent(effectiveRoot) + "&" : "";
    return "/api/artifact?" + rootQuery + "path=" + encodeURIComponent(artifactPath);
  }

  function artifactDownloadHrefFor(artifact) {
    const direct = readAny(artifact, ["href", "url"]);
    if (isExternalUrl(direct)) {
      return "";
    }
    return artifactDownloadHref(readField(artifact, "path") || direct);
  }

  function artifactDownloadHref(path) {
    const href = artifactHref(path);
    if (!href || isExternalUrl(href)) {
      return "";
    }
    return href + (href.indexOf("?") >= 0 ? "&" : "?") + "download=1";
  }

  function normalizeArtifactPath(path) {
    if (!path || typeof path !== "string") {
      return "";
    }
    const trimmed = path.trim();
    if (!trimmed || isExternalUrl(trimmed)) {
      return trimmed;
    }
    return trimmed.replace(/^\/+/, "");
  }

  function isExternalUrl(value) {
    return typeof value === "string" && /^(https?:)?\/\//.test(value);
  }

  function codeText(value) {
    return '<code class="mono">' + escapeHtml(value) + "</code>";
  }

  function emptyState(message) {
    return '<div class="empty-state">' + escapeHtml(message) + "</div>";
  }

  function tableEmptyRow(message) {
    return '<tr><td colspan="9" class="empty-state">' + escapeHtml(message) + "</td></tr>";
  }

  function emptyTimeline(message) {
    return '<li class="empty-state">' + escapeHtml(message) + "</li>";
  }

  function renderEventDetails(details) {
    if (!details || typeof details !== "object") {
      return "";
    }
    return (
      '<details class="details-json"><summary>details</summary><pre>' +
      escapeHtml(JSON.stringify(details, null, 2)) +
      "</pre></details>"
    );
  }

  function renderWarning(warning) {
    const artifact = readField(warning, "artifact");
    const path = readField(warning, "path");
    const message = readField(warning, "message") || String(warning || "");
    const meta = [
      artifact ? "artifact " + artifact : null,
      path ? "path " + path : null,
    ]
      .filter(Boolean)
      .join(" / ");
    return (
      '<div class="warning-item">' +
      (meta ? '<div class="mono">' + escapeHtml(meta) + "</div>" : "") +
      "<div>" +
      escapeHtml(message) +
      "</div></div>"
    );
  }

  function setBadge(element, value, className) {
    element.className = "badge " + (className || "neutral");
    element.textContent = valueOrDash(value);
  }

  function statusClass(value) {
    const normalized = normalizeClass(value);
    if (!normalized) {
      return "neutral";
    }
    if (["running", "started", "observed"].includes(normalized)) {
      return normalized;
    }
    if (["succeeded", "passed"].includes(normalized)) {
      return "succeeded";
    }
    if (["failed", "error"].includes(normalized)) {
      return "failed";
    }
    return "neutral";
  }

  function severityClass(value) {
    const normalized = normalizeClass(value);
    if (!normalized) {
      return "neutral";
    }
    if (normalized === "degraded") {
      return "degraded";
    }
    if (normalized === "needs-investigation") {
      return "needs-investigation";
    }
    if (normalized === "infra") {
      return "infra";
    }
    if (["fail-correctness", "fail-availability", "failed"].includes(normalized)) {
      return normalized;
    }
    return statusClass(value);
  }

  function normalizeClass(value) {
    return String(value || "")
      .trim()
      .toLowerCase()
      .replace(/_/g, "-");
  }

  function pick(object, keys) {
    if (!object || typeof object !== "object") {
      return undefined;
    }
    for (const key of keys) {
      if (Object.prototype.hasOwnProperty.call(object, key) && object[key] !== undefined) {
        return object[key];
      }
    }
    return undefined;
  }

  function readField(object, key) {
    return pick(object, [key].concat(LEGACY_FIELD_ALIASES[key] || []));
  }

  function readAny(object, keys) {
    for (const key of keys) {
      const value = readField(object, key);
      if (value !== undefined) {
        return value;
      }
    }
    return undefined;
  }

  function firstObject() {
    for (const item of arguments) {
      if (item && typeof item === "object" && !Array.isArray(item)) {
        return item;
      }
    }
    return null;
  }

  function asArray(value) {
    if (Array.isArray(value)) {
      return value;
    }
    if (value === undefined || value === null || value === "") {
      return [];
    }
    return [value];
  }

  function collectWarnings(target, value) {
    asArray(value).forEach(function (item) {
      const warning = normalizeWarning(item);
      if (warning) {
        target.push(warning);
      }
    });
  }

  function normalizeWarning(item) {
    if (typeof item === "string") {
      return { artifact: "", path: "", message: item };
    }
    if (!item || typeof item !== "object") {
      return null;
    }
    return {
      artifact: String(readField(item, "artifact") || ""),
      path: String(readField(item, "path") || ""),
      message: String(readAny(item, ["message", "warning", "reason"]) || JSON.stringify(item)),
    };
  }

  function uniqueWarnings(warnings) {
    const seen = new Set();
    return warnings.filter(function (warning) {
      const key = [warning.artifact, warning.path, warning.message].join("|");
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  function uniqueStrings(values) {
    return Array.from(new Set(values.filter(Boolean)));
  }

  function attemptNumber(attempt) {
    const index = readField(attempt, "index");
    return typeof index === "number" ? index : valueOrDash(index);
  }

  function attemptReason(attempt) {
    const direct = readAny(attempt, ["error", "reason", "message"]);
    if (direct) {
      return direct;
    }
    const failedCase = asArray(readField(attempt, "cases")).find(function (testCase) {
      return readField(testCase, "failureSummary");
    });
    const failure = failedCase && readField(failedCase, "failureSummary");
    return readAny(failure, ["message", "reason", "stage"]);
  }

  function formatStopPolicy(stopOnFirst, continueOn) {
    if (stopOnFirst === undefined && !asArray(continueOn).length) {
      return "-";
    }
    const base = stopOnFirst === false ? "continue" : "stop first";
    const severities = asArray(continueOn);
    return severities.length ? base + " except " + severities.join(", ") : base;
  }

  function elapsedSeconds(started, ended) {
    if (!started) {
      return null;
    }
    const start = Number(started);
    const end = Number(ended || Date.now());
    if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) {
      return null;
    }
    return Math.round((end - start) / 1000);
  }

  function formatDuration(seconds) {
    if (seconds === undefined || seconds === null || seconds === "") {
      return "-";
    }
    const total = Number(seconds);
    if (!Number.isFinite(total)) {
      return String(seconds);
    }
    const h = Math.floor(total / 3600);
    const m = Math.floor((total % 3600) / 60);
    const s = Math.floor(total % 60);
    if (h) {
      return h + "h " + m + "m";
    }
    if (m) {
      return m + "m " + s + "s";
    }
    return s + "s";
  }

  function secondsValue(value) {
    if (value === undefined || value === null || value === "") {
      return "";
    }
    return formatDuration(value);
  }

  function formatTime(value) {
    if (value === undefined || value === null || value === "") {
      return "-";
    }
    const ms = Number(value);
    if (!Number.isFinite(ms)) {
      return String(value);
    }
    return new Date(ms).toLocaleString(undefined, {
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }

  function formatBool(value) {
    if (value === undefined || value === null || value === "") {
      return "-";
    }
    return value ? "true" : "false";
  }

  function valueOrDash(value) {
    if (value === undefined || value === null || value === "") {
      return "-";
    }
    return value;
  }

  function compactJson(value) {
    if (value === undefined || value === null || value === "") {
      return "-";
    }
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      return escapeHtml(String(value));
    }
    return '<code class="mono">' + escapeHtml(JSON.stringify(value)) + "</code>";
  }

  function compactText(value) {
    if (value === undefined || value === null || value === "") {
      return "-";
    }
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      return String(value);
    }
    return JSON.stringify(value);
  }

  function targetSummary(value) {
    if (!value || typeof value !== "object") {
      return String(value || "");
    }
    return (
      pick(value, ["summary"]) ||
      [pick(value, ["kind"]), pick(value, ["value"]), pick(value, ["path"])]
        .filter(function (item) {
          return item !== undefined && item !== null && item !== "";
        })
        .join(":") ||
      JSON.stringify(value)
    );
  }

  function basename(path) {
    return String(path || "").split(/[\\/]/).filter(Boolean).pop() || "artifact";
  }

  function renderLastRefresh() {
    if (state.loading) {
      dom.lastRefresh.textContent = "Loading...";
    } else if (state.lastLoadedAt) {
      dom.lastRefresh.textContent =
        "Last refresh " + state.lastLoadedAt.toLocaleTimeString();
    } else {
      dom.lastRefresh.textContent = "Not loaded";
    }
  }

  function showBanner(kind, message) {
    dom.banner.hidden = false;
    dom.banner.className = "status-banner " + kind;
    dom.banner.textContent = message;
  }

  function hideBanner() {
    dom.banner.hidden = true;
    dom.banner.className = "status-banner";
    dom.banner.textContent = "";
  }

  function updateUrlRoot(root) {
    const url = new URL(window.location.href);
    if (root) {
      url.searchParams.set("root", root);
    } else {
      url.searchParams.delete("root");
    }
    window.history.replaceState(null, "", url);
  }

  function readStorage(key) {
    try {
      return window.localStorage.getItem(key) || "";
    } catch (_) {
      return "";
    }
  }

  function writeStorage(key, value) {
    try {
      window.localStorage.setItem(key, value);
    } catch (_) {
      // localStorage can be unavailable in private or file contexts.
    }
  }

  function removeStorage(key) {
    try {
      window.localStorage.removeItem(key);
    } catch (_) {
      // localStorage can be unavailable in private or file contexts.
    }
  }

  function truthy(value) {
    return value === true || value === "true" || value === 1 || value === "1";
  }

  function falsy(value) {
    return value === false || value === "false" || value === 0 || value === "0";
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function escapeAttr(value) {
    return escapeHtml(value).replace(/`/g, "&#96;");
  }
})();
