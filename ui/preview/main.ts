// Every view with sample data, each in a box the width of a chat message,
// with a theme switch. Stands in for the host: links open in a new tab and
// get_subject_by_id answers from the fixtures.

import { el, type Host, type Render } from "../src/host";
import { render as subject } from "../src/views/subject";
import { render as subjects } from "../src/views/subjects";
import { render as progress } from "../src/views/progress";
import { FIND_NEW_KANJI, FIND_NEW_VOCABULARY, GET_KANJI, GET_VOCABULARY, PROGRESS, SUBJECTS } from "./fixtures";

const host: Host = {
  openLink: (url) => window.open(url, "_blank", "noopener"),
  getSubject: async (id) => {
    const found = SUBJECTS[id];
    if (!found) throw new Error(`no sample for subject ${id}`);
    return { subjects: [found], not_found: [] };
  },
};

const views: [string, Render<never>, unknown][] = [
  ["get_level_info → ui://wanikani/progress", progress, PROGRESS],
  ["get_kanji_by_character → ui://wanikani/subject", subject, GET_KANJI],
  ["get_vocabulary_by_phrase → ui://wanikani/subject", subject, GET_VOCABULARY],
  ["find_new_kanji_from_sentence → ui://wanikani/subjects", subjects, FIND_NEW_KANJI],
  ["find_new_vocabulary → ui://wanikani/subjects", subjects, FIND_NEW_VOCABULARY],
];

const page = document.getElementById("preview")!;
page.style.cssText = "display:grid;gap:20px;padding:20px 16px;max-width:680px;margin:0 auto;";

const themes = el("div", { class: "seg" });
themes.style.cssText = "display:flex;gap:6px;";
for (const theme of ["system", "light", "dark"]) {
  const button = el("button", { type: "button", class: "chip" }, theme);
  button.addEventListener("click", () => {
    if (theme === "system") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = theme;
  });
  themes.append(button);
}
page.append(themes);

for (const [title, render, output] of views) {
  const frame = el("div");
  frame.style.cssText = "border:1px dashed var(--color-border-primary);border-radius:var(--border-radius-lg);";
  page.append(el("p", { class: "meta" }, title), frame);
  (render as Render<unknown>)(frame, host, output);
}
