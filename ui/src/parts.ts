// Pieces the views share: the subject tile, the subject card, mnemonic
// markup and hints.

import { el } from "./host";
import type { Markup, SrsGroup, SrsStage, SubjectCard, SubjectType } from "./output";

export const TYPE_LABEL: Record<SubjectType, string> = {
  radical: "Radical",
  kanji: "Kanji",
  vocabulary: "Vocabulary",
  kana_vocabulary: "Vocabulary",
};

/** The colour family a subject type draws in. */
function family(type: SubjectType): "radical" | "kanji" | "vocabulary" {
  return type === "kana_vocabulary" ? "vocabulary" : type;
}

export const SRS_GROUPS: [SrsGroup, string][] = [
  ["apprentice", "Apprentice"],
  ["guru", "Guru"],
  ["master", "Master"],
  ["enlightened", "Enlightened"],
  ["burned", "Burned"],
];

export function srsGroup(stage: SrsStage): SrsGroup | null {
  if (stage === null || stage === 0) return null;
  if (stage <= 4) return "apprentice";
  if (stage <= 6) return "guru";
  if (stage === 7) return "master";
  if (stage === 8) return "enlightened";
  return "burned";
}

const NUMERALS = ["", "I", "II", "III", "IV"];

export function srsName(stage: SrsStage): string {
  if (stage === null) return "Locked";
  if (stage === 0) return "Lesson";
  if (stage <= 4) return `Apprentice ${NUMERALS[stage]}`;
  if (stage <= 6) return `Guru ${NUMERALS[stage - 4]}`;
  return SRS_GROUPS.find(([group]) => group === srsGroup(stage))![1];
}

/** The character on its type's colour. `lg` heads the subject view; `md`
 * sits in cards; `sm` in chips and the level grid. */
export function tile(card: SubjectCard, size: "lg" | "md" | "sm"): HTMLElement {
  const node = el("span", { class: `tile tile-${family(card.type)} tile-${size}` });
  if (card.characters) {
    node.lang = "ja";
    node.append(card.characters);
  } else if (card.character_image) {
    node.append(el("img", { src: card.character_image, alt: card.meaning }));
  } else {
    node.append(card.meaning);
  }
  return node;
}

/** A tile with its reading and meaning, in a grid. */
export function card(subject: SubjectCard, open: () => void, extra?: string): HTMLElement {
  const group = srsGroup(subject.srs_stage);
  const button = el(
    "button",
    { class: "subject-card", type: "button", title: `${TYPE_LABEL[subject.type]} · level ${subject.level} · ${srsName(subject.srs_stage)}` },
    tile(subject, "md"),
    subject.reading ? el("span", { class: "reading", lang: "ja" }, subject.reading) : null,
    el("span", { class: "meaning" }, subject.meaning),
    extra ? el("span", { class: "extra" }, extra) : null,
  );
  if (group) button.append(el("span", { class: `stage-dot ${group}`, ariaHidden: "true" }));
  button.addEventListener("click", open);
  return button;
}

/** A small tile with its meaning beside it, for a subject's components. */
export function chip(subject: SubjectCard, open: () => void): HTMLElement {
  const button = el(
    "button",
    { class: "subject-chip", type: "button" },
    tile(subject, "sm"),
    el("span", {}, subject.meaning),
  );
  button.addEventListener("click", open);
  return button;
}

const MARKS: Record<string, string> = {
  radical: "mark mark-radical",
  kanji: "mark mark-kanji",
  vocabulary: "mark mark-vocabulary",
  reading: "mark mark-reading",
  meaning: "mark mark-meaning",
  ja: "ja",
};

/** WaniKani's mnemonic markup as highlights. The markup is parsed into an
 * inert document and only its text and the tags in MARKS are copied out, so
 * nothing in it runs or renders as HTML. */
export function markup(source: Markup): DocumentFragment {
  const parsed = new DOMParser().parseFromString(`<body>${source}</body>`, "text/html");
  const out = document.createDocumentFragment();
  copy(parsed.body, out);
  return out;
}

function copy(from: Node, to: Node) {
  for (const node of from.childNodes) {
    if (node.nodeType === Node.TEXT_NODE) {
      to.appendChild(document.createTextNode(node.textContent ?? ""));
    } else if (node instanceof Element) {
      const className = MARKS[node.tagName.toLowerCase()];
      if (className) {
        const span = el("span", { class: className });
        if (className === "ja") span.lang = "ja";
        copy(node, span);
        to.appendChild(span);
      } else {
        copy(node, to);
      }
    }
  }
}

export function hint(text: Markup): HTMLElement {
  return el("aside", { class: "hint" }, el("strong", {}, "Hint"), el("p", {}, markup(text)));
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}
