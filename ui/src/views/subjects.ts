// ui://wanikani/subjects: a grid of subjects the user has not learned yet,
// for find_new_kanji_from_sentence and find_new_vocabulary, in the order
// WaniKani teaches them. Each card opens the subject on wanikani.com.

import { el, type Host } from "../host";
import type { SubjectCard, SubjectsOutput } from "../output";
import { card, plural } from "../parts";

export function render(root: HTMLElement, host: Host, output: SubjectsOutput) {
  const kanji = "sentence" in output;
  const heading = kanji ? "New kanji" : "New vocabulary";
  const meta = plural(output.subjects.length, kanji ? "kanji" : "word", kanji ? "kanji" : "words");

  const view = el(
    "div",
    { class: "view" },
    el("div", { class: "head" }, el("h1", {}, heading), el("span", { class: "meta" }, meta)),
  );
  if (kanji) view.append(el("p", { class: "source", lang: "ja" }, highlight(output.sentence, output.subjects)));

  if (output.subjects.length) {
    const sorted = [...output.subjects].sort((a, b) => a.level - b.level);
    view.append(
      el("div", { class: "grid" }, ...sorted.map((subject) => card(subject, () => host.openLink(subject.url), `Level ${subject.level}`))),
    );
  }
  if (!output.subjects.length) view.append(el("p", { class: "empty" }, kanji ? "You know every kanji here." : "You know every word here."));
  if ("not_found" in output && output.not_found.length) {
    view.append(el("p", { class: "meta" }, `Not on WaniKani: ${output.not_found.join("、")}`));
  }
  root.replaceChildren(view);
}

/** The sentence with each new kanji marked. */
function highlight(sentence: string, subjects: SubjectCard[]): DocumentFragment {
  const fresh = new Set(subjects.map((subject) => subject.characters));
  const out = document.createDocumentFragment();
  for (const character of sentence) {
    out.append(fresh.has(character) ? el("span", { class: "mark mark-kanji" }, character) : character);
  }
  return out;
}
