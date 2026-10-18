import {
  analyzeText,
  applyMappings,
  verifyOutput,
  DEFAULT_REDACT_OPTIONS,
  type GeoMode,
  type IpAliasStyle,
  type MappingEntry,
  type RedactOptions,
} from "@core/index";
import { t } from "@i18n/index";

interface AppState {
  input: string;
  mappings: MappingEntry[];
  output: string;
  remainingCount: number;
  analyzed: boolean;
  redactInternalIds: boolean;
  redactBusinessIds: boolean;
  geoMode: GeoMode;
  ipStyle: IpAliasStyle;
}

/** The preview is capped for rendering speed; the downloaded file is always complete. */
const PREVIEW_LIMIT = 8000;

export function mountApp(root: HTMLElement): void {
  const m = t();
  const state: AppState = {
    input: "",
    mappings: [],
    output: "",
    remainingCount: 0,
    analyzed: false,
    redactInternalIds: false,
    redactBusinessIds: false,
    geoMode: "mask",
    ipStyle: "preserveClass",
  };

  root.replaceChildren();
  root.className = "page";

  const header = el("header", { className: "header" }, [
    el("h1", {}, [m.appTitle]),
    el("p", { className: "trust" }, [
      m.tagline,
      " ",
      link(m.verifyHow, "./limits.html"),
    ]),
  ]);

  const optionsPanel = el("div", { className: "panel options" }, [
    el("p", { className: "options-title" }, [m.options]),
    el("label", { className: "option" }, [
      checkbox(false, (checked) => {
        state.redactInternalIds = checked;
        if (state.analyzed) runAnalyze();
      }),
      " ",
      m.redactInternalIds,
    ]),
    el("label", { className: "option" }, [
      checkbox(false, (checked) => {
        state.redactBusinessIds = checked;
        if (state.analyzed) runAnalyze();
      }),
      " ",
      m.redactBusinessIds,
    ]),
    el("div", { className: "option row" }, [
      el("span", {}, [m.geoModeLabel]),
      radioGroup(
        "geo-mode",
        [
          { value: "mask", label: m.geoMask },
          { value: "round", label: m.geoRound },
        ],
        state.geoMode,
        (value) => {
          state.geoMode = value as GeoMode;
          if (state.analyzed) runAnalyze();
        },
      ),
    ]),
    el("div", { className: "option row" }, [
      el("span", {}, [m.ipStyleLabel]),
      radioGroup(
        "ip-style",
        [
          { value: "preserveClass", label: m.ipPreserveClass },
          { value: "label", label: m.ipLabel },
        ],
        state.ipStyle,
        (value) => {
          state.ipStyle = value as IpAliasStyle;
          if (state.analyzed) runAnalyze();
        },
      ),
    ]),
  ]);

  const deposit = section(m.stepDeposit, [
    el("div", { className: "drop", id: "drop" }, [
      el("p", {}, [m.dropHint]),
      el("p", {}, [m.orPaste]),
      el("div", { className: "row" }, [
        fileButton(m.chooseFile, (text) => {
          state.input = text;
          paste.value = text;
          resetAnalysis();
          renderReview();
        }),
      ]),
    ]),
    el("textarea", {
      id: "paste",
      placeholder: m.pastePlaceholder,
      spellcheck: "false",
    }),
    optionsPanel,
    el("div", { className: "row actions" }, [
      button(m.analyze, () => runAnalyze(), "primary"),
      button(m.clear, () => {
        state.input = "";
        paste.value = "";
        resetAnalysis();
        renderReview();
      }),
    ]),
  ]);

  const reviewHost = el("div", {});
  const downloadHost = el("div", {});

  root.append(header, deposit, reviewHost, downloadHost);
  root.append(
    el("p", { className: "nav-links" }, [link(m.limitsLink, "./limits.html")]),
  );

  const paste = deposit.querySelector("#paste") as HTMLTextAreaElement;
  const drop = deposit.querySelector("#drop") as HTMLElement;

  paste.addEventListener("input", () => {
    state.input = paste.value;
    resetAnalysis();
    renderReview();
  });

  drop.addEventListener("dragover", (event) => {
    event.preventDefault();
    drop.classList.add("dragover");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("dragover"));
  drop.addEventListener("drop", async (event) => {
    event.preventDefault();
    drop.classList.remove("dragover");
    const file = event.dataTransfer?.files?.[0];
    if (!file) return;
    const text = await file.text();
    state.input = text;
    paste.value = text;
    resetAnalysis();
    renderReview();
  });

  function currentOptions(): RedactOptions {
    return {
      ...DEFAULT_REDACT_OPTIONS,
      redactInternalIds: state.redactInternalIds,
      redactBusinessIds: state.redactBusinessIds,
      alias: {
        ...DEFAULT_REDACT_OPTIONS.alias,
        geoMode: state.geoMode,
        ipStyle: state.ipStyle,
      },
    };
  }

  function resetAnalysis(): void {
    state.analyzed = false;
    state.mappings = [];
    state.output = "";
    state.remainingCount = 0;
  }

  function runAnalyze(): void {
    state.input = paste.value;
    const analyzed = analyzeText(state.input, currentOptions());
    state.mappings = analyzed.mappings.map((entry) => ({ ...entry }));
    const applied = applyMappings(state.input, state.mappings);
    state.output = applied.output;
    state.remainingCount = verifyOutput(state.output, state.mappings).remaining.length;
    state.analyzed = true;
    renderReview();
  }

  function recomputeOutput(): void {
    const applied = applyMappings(state.input, state.mappings);
    state.output = applied.output;
    state.remainingCount = verifyOutput(state.output, state.mappings).remaining.length;
    renderReview();
  }

  function renderReview(): void {
    reviewHost.replaceChildren();
    downloadHost.replaceChildren();

    if (!state.analyzed) {
      reviewHost.append(
        section(m.stepReview, [el("p", { className: "muted" }, [m.emptyState])]),
      );
      downloadHost.append(
        section(m.stepDownload, [el("p", { className: "muted" }, ["-"])]),
      );
      return;
    }

    const byKind = state.mappings.reduce<Record<string, number>>((acc, entry) => {
      acc[entry.kind] = (acc[entry.kind] ?? 0) + 1;
      return acc;
    }, {});
    const summaryBits = Object.entries(byKind)
      .map(([kind, count]) => `${count} ${kind}`)
      .join(" · ");

    const table = el("table", { className: "table" }, [
      el("thead", {}, [
        el("tr", {}, [
          el("th", {}, [m.colDecision]),
          el("th", {}, [m.colType]),
          el("th", {}, [m.colOrigin]),
          el("th", {}, [m.colAlias]),
          el("th", {}, [m.occurrenceLabel]),
        ]),
      ]),
      el(
        "tbody",
        {},
        state.mappings.map((entry, index) =>
          el("tr", {}, [
            el("td", {}, [
              checkbox(entry.decision === "replace", (checked) => {
                const current = state.mappings[index];
                if (!current) return;
                current.decision = checked ? "replace" : "keep";
                recomputeOutput();
              }),
            ]),
            el("td", {}, [entry.kind]),
            el("td", {}, [entry.original]),
            el("td", {}, [
              entry.decision === "replace"
                ? entry.alias
                : `${entry.original} (${m.keptHint})`,
            ]),
            el("td", {}, [String(entry.occurrenceCount)]),
          ]),
        ),
      ),
    ]);

    reviewHost.append(
      section(m.stepReview, [
        el("p", { className: "summary" }, [
          `${m.summary}${m.colon}${summaryBits || "0"} · ${state.mappings.length} ${m.uniqueLabel}`,
        ]),
        el("h3", {}, [m.mappings]),
        state.mappings.length > 0
          ? el("div", { className: "table-wrap", tabindex: "0", role: "region", "aria-label": m.mappings }, [table])
          : el("p", { className: "muted" }, [m.noValues]),
        el("h3", {}, [m.preview]),
        el("pre", { className: "code", tabindex: "0", "aria-label": m.preview }, [state.output.slice(0, PREVIEW_LIMIT)]),
        ...(state.output.length > PREVIEW_LIMIT
          ? [el("p", { className: "muted" }, [m.previewTruncated(PREVIEW_LIMIT, state.output.length)])]
          : []),
      ]),
    );

    const control =
      state.remainingCount === 0
        ? el("p", { className: "status-ok" }, [m.controlOk])
        : el("p", { className: "status-warn" }, [m.controlWarn(state.remainingCount)]);

    downloadHost.append(
      section(m.stepDownload, [
        control,
        el("div", { className: "row" }, [
          button(m.downloadClean, () =>
            downloadText("logs-redacted.txt", state.output),
          ),
          button(m.downloadReport, () =>
            downloadText(
              "redaction-report.json",
              JSON.stringify(
                {
                  generatedAt: new Date().toISOString(),
                  uniqueValues: state.mappings.length,
                  byKind,
                  replacements: state.mappings
                    .filter((entry) => entry.decision === "replace")
                    .map((entry) => ({
                      kind: entry.kind,
                      alias: entry.alias,
                      occurrenceCount: entry.occurrenceCount,
                    })),
                  remainingOriginalsInOutput: state.remainingCount,
                },
                null,
                2,
              ),
            ),
          ),
        ]),
      ]),
    );
  }

  renderReview();
}

function section(title: string, children: Array<Node | string>): HTMLElement {
  return el("section", { className: "section" }, [
    el("h2", {}, [title]),
    ...children,
  ]);
}

function button(label: string, onClick: () => void, className = ""): HTMLButtonElement {
  const node = el("button", { type: "button", className }, [label]) as HTMLButtonElement;
  node.addEventListener("click", onClick);
  return node;
}

function fileButton(label: string, onText: (text: string) => void): HTMLElement {
  const input = el("input", {
    type: "file",
    className: "hidden-input",
    accept: ".log,.txt,.json,.jsonl,.ndjson,.csv,.xml,.eml,.ldif,text/plain,application/json",
  }) as HTMLInputElement;
  const control = el("label", { className: "file-btn" }, [label, input]);
  input.addEventListener("change", async () => {
    const file = input.files?.[0];
    if (!file) return;
    onText(await file.text());
    input.value = "";
  });
  return control;
}

function checkbox(checked: boolean, onChange: (checked: boolean) => void): HTMLInputElement {
  const node = el("input", { type: "checkbox" }) as HTMLInputElement;
  node.checked = checked;
  node.setAttribute("aria-label", checked ? t().replace : t().keep);
  node.addEventListener("change", () => onChange(node.checked));
  return node;
}

function radioGroup(
  name: string,
  choices: Array<{ value: string; label: string }>,
  selected: string,
  onChange: (value: string) => void,
): HTMLElement {
  const wrap = el("div", { className: "row" }, []);
  for (const choice of choices) {
    const input = el("input", {
      type: "radio",
      name,
      value: choice.value,
    }) as HTMLInputElement;
    input.checked = choice.value === selected;
    input.addEventListener("change", () => {
      if (input.checked) onChange(choice.value);
    });
    wrap.append(el("label", { className: "option" }, [input, " ", choice.label]));
  }
  return wrap;
}

function link(label: string, href: string): HTMLAnchorElement {
  return el("a", { href }, [label]) as HTMLAnchorElement;
}

function downloadText(filename: string, content: string): void {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = el("a", { href: url, download: filename }) as HTMLAnchorElement;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  // Revoking right away can cancel the download in Firefox/Safari.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function el(
  tag: string,
  attrs: Record<string, string> = {},
  children: Array<Node | string> = [],
): HTMLElement {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "className") node.className = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    node.append(child);
  }
  return node;
}
