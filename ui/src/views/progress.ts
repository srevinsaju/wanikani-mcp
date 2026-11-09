// ui://wanikani/progress: get_level_info as what is waiting now, how far the
// current level is, every subject on it by SRS stage, and the next day's
// reviews.

import { el, type Host } from "../host";
import type { ProgressOutput, SubjectCard } from "../output";
import { plural, SRS_GROUPS, srsGroup, srsName, tile } from "../parts";

/** WaniKani levels you up once this share of the level's kanji is Guru. */
const LEVEL_UP_SHARE = 0.9;

export function render(root: HTMLElement, host: Host, output: ProgressOutput) {
  const days = output.level_started_at ? Math.floor((Date.now() - Date.parse(output.level_started_at)) / 86_400_000) : null;
  const meta = [output.username, days !== null ? `day ${days + 1} on this level` : null].filter(Boolean).join(" · ");
  const upcoming = output.forecast.reduce((sum, hour) => sum + hour.reviews, 0);

  root.replaceChildren(
    el(
      "div",
      { class: "view" },
      el("div", { class: "head" }, el("h1", {}, `Level ${output.level}`), el("span", { class: "meta" }, meta)),
      el(
        "div",
        { class: "totals" },
        total("Lessons", output.lessons_available, "available"),
        total("Reviews", output.reviews_available, "available now"),
        total("Next 24h", upcoming, "reviews"),
      ),
      levelProgress(output),
      levelGrid(host, output.level_subjects),
      srs(output),
      output.forecast.length ? forecast(output) : null,
    ),
  );
}

function total(label: string, value: number, unit: string): HTMLElement {
  return el("div", { class: "total" }, el("span", { class: "meta" }, label), el("strong", {}, String(value)), el("span", { class: "meta" }, unit));
}

function levelProgress(output: ProgressOutput): HTMLElement {
  const { passed, total } = output.level_kanji;
  const needed = Math.ceil(total * LEVEL_UP_SHARE);
  const left = Math.max(needed - passed, 0);
  const note = left ? `${plural(left, "more kanji", "more kanji")} to Guru to level up` : "Ready to level up";
  return el(
    "section",
    { class: "section" },
    el("h2", {}, "This level"),
    meter("Radicals", output.level_radicals.passed, output.level_radicals.total, "radical"),
    meter("Kanji", passed, total, "kanji", needed / total),
    el("p", { class: "meta" }, note),
  );
}

/** A bar of `passed` out of `total`, with an optional target tick (0 to 1). */
function meter(label: string, passed: number, total: number, type: "radical" | "kanji", target?: number): HTMLElement {
  const fill = el("i", { class: `fill-${type}` });
  fill.style.width = `${total ? (passed / total) * 100 : 0}%`;
  const bar = el("div", { class: "meter-bar", role: "img", ariaLabel: `${label}: ${passed} of ${total} passed` }, fill);
  if (target !== undefined) {
    const tick = el("b", { class: "target" });
    tick.style.left = `${target * 100}%`;
    bar.append(tick);
  }
  return el("div", { class: "meter" }, el("span", {}, label), bar, el("span", { class: "meta" }, `${passed}/${total}`));
}

/** Every subject on the level: locked ones faded, the rest underlined in
 * their SRS stage's colour. */
function levelGrid(host: Host, subjects: SubjectCard[]): HTMLElement | null {
  if (!subjects.length) return null;
  return el(
    "div",
    { class: "level-grid" },
    ...subjects.map((subject) => {
      const group = srsGroup(subject.srs_stage);
      const button = el(
        "button",
        { class: `level-item ${subject.srs_stage === null ? "locked" : ""} ${group ?? ""}`, type: "button", title: `${subject.meaning} · ${srsName(subject.srs_stage)}` },
        tile(subject, "sm"),
      );
      button.addEventListener("click", () => host.openLink(subject.url));
      return button;
    }),
  );
}

function srs(output: ProgressOutput): HTMLElement {
  const count = SRS_GROUPS.reduce((sum, [group]) => sum + output.srs[group], 0);
  const bar = el("div", { class: "stack", role: "img" });
  bar.ariaLabel = SRS_GROUPS.map(([group, label]) => `${label} ${output.srs[group]}`).join(", ");
  const legend = el("ul", { class: "legend" });
  for (const [group, label] of SRS_GROUPS) {
    const n = output.srs[group];
    if (n) {
      const segment = el("i", { class: group });
      segment.style.flex = String(n);
      bar.append(segment);
    }
    legend.append(el("li", {}, el("i", { class: group }), label, el("b", {}, String(n))));
  }
  return el("section", { class: "section" }, el("h2", {}, `${count.toLocaleString()} ${count === 1 ? "item" : "items"} in reviews`), bar, legend);
}

/** One column per hour that has reviews, tallest scaled to the box. */
function forecast(output: ProgressOutput): HTMLElement {
  const peak = Math.max(...output.forecast.map((hour) => hour.reviews));
  const columns = output.forecast.map((hour) => {
    const column = el("i");
    column.style.height = `${(hour.reviews / peak) * 100}%`;
    const time = new Date(hour.at).toLocaleTimeString(undefined, { hour: "numeric" });
    return el("div", { class: "hour", title: `${time}: ${plural(hour.reviews, "review")}` }, el("span", { class: "count" }, String(hour.reviews)), el("div", { class: "column" }, column), el("span", { class: "meta" }, time));
  });
  return el("section", { class: "section" }, el("h2", {}, "Coming up"), el("div", { class: "forecast" }, ...columns));
}
