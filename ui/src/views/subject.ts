// ui://wanikani/subject: one subject's meanings, readings, mnemonics and
// related subjects, for get_subject_by_id, get_kanji_by_character and
// get_vocabulary_by_phrase. Several subjects show as a strip to switch
// between. A related subject opens in place, with a way back.

import { el, type Host } from "../host";
import type { GetSubjectsOutput, Reading, Subject, SubjectCard } from "../output";
import { card, chip, hint, markup, plural, srsName, tile, TYPE_LABEL } from "../parts";

/** Related subjects beyond this many sit behind "Show all". */
const RELATED_LIMIT = 8;

const READING_LABEL = { onyomi: "On’yomi", kunyomi: "Kun’yomi", nanori: "Nanori" } as const;

export function render(root: HTMLElement, host: Host, output: GetSubjectsOutput) {
  const history: GetSubjectsOutput[] = [];
  let selected = 0;

  const draw = () => {
    const current = history.at(-1) ?? output;
    const subject = current.subjects[selected];
    const view = el("div", { class: "view" });
    if (history.length) {
      const previous = history.length > 1 ? history.at(-2)! : output;
      const back = el("button", { class: "back", type: "button" }, `← ${label(previous.subjects[0])}`);
      back.addEventListener("click", () => {
        history.pop();
        selected = 0;
        draw();
      });
      view.append(back);
    }
    if (current.subjects.length > 1) view.append(switcher(current.subjects, selected, (index) => {
      selected = index;
      draw();
    }));
    if (current.not_found.length) {
      view.append(el("p", { class: "meta" }, `Not on WaniKani: ${current.not_found.join("、")}`));
    }
    if (subject) {
      view.append(...detail(host, subject, (id) => open(id)));
    }
    if (!subject && !current.not_found.length) view.append(el("p", { class: "empty" }, "Nothing here."));
    root.replaceChildren(view);
  };

  const open = async (id: number) => {
    try {
      history.push(await host.getSubject(id));
      selected = 0;
      draw();
    } catch (error) {
      root.append(el("p", { class: "error", role: "status" }, String(error)));
    }
  };

  draw();
}

function label(subject: SubjectCard | undefined): string {
  return subject ? (subject.characters ?? subject.meaning) : "Back";
}

function switcher(subjects: Subject[], selected: number, pick: (index: number) => void): HTMLElement {
  const strip = el("div", { class: "switcher", role: "group" });
  subjects.forEach((subject, index) => {
    const button = el("button", { type: "button", title: subject.meaning }, tile(subject, "sm"));
    button.setAttribute("aria-pressed", String(index === selected));
    button.addEventListener("click", () => pick(index));
    strip.append(button);
  });
  return strip;
}

function detail(host: Host, subject: Subject, open: (id: number) => void): HTMLElement[] {
  const [primary, ...others] = subject.meanings;
  const link = el("button", { class: "chip", type: "button" }, "wanikani.com ↗");
  link.addEventListener("click", () => host.openLink(subject.url));

  const head = el(
    "header",
    { class: "subject-head" },
    tile(subject, "lg"),
    el(
      "div",
      {},
      el("h1", {}, primary ?? subject.meaning),
      el("div", { class: "meta" }, [TYPE_LABEL[subject.type], `Level ${subject.level}`, ...subject.parts_of_speech].join(" · ")),
      el(
        "div",
        { class: "chips" },
        el("span", { class: `chip stage ${subject.srs_stage === null ? "locked" : ""}` }, srsName(subject.srs_stage)),
        link,
      ),
    ),
  );

  const parts: HTMLElement[] = [head];

  const meaning = section("Meaning");
  if (others.length) meaning.append(el("p", { class: "meta" }, `Also ${others.join(", ")}`));
  meaning.append(el("p", { class: "mnemonic" }, markup(subject.meaning_mnemonic)));
  if (subject.meaning_hint) meaning.append(hint(subject.meaning_hint));
  parts.push(meaning);

  if (subject.readings.length) {
    const reading = section("Reading");
    reading.append(readings(subject));
    if (subject.reading_mnemonic) reading.append(el("p", { class: "mnemonic" }, markup(subject.reading_mnemonic)));
    if (subject.reading_hint) reading.append(hint(subject.reading_hint));
    parts.push(reading);
  }

  if (subject.components.length) {
    const title = subject.type === "kanji" ? "Radicals" : "Kanji";
    parts.push(section(title, el("div", { class: "chip-row" }, ...subject.components.map((part) => chip(part, () => open(part.id))))));
  }

  if (subject.context_sentences.length) {
    parts.push(
      section(
        "Context",
        ...subject.context_sentences.slice(0, 3).map((sentence) =>
          el("p", { class: "sentence" }, el("span", { lang: "ja" }, sentence.ja), el("span", { class: "meta" }, sentence.en)),
        ),
      ),
    );
  }

  if (subject.visually_similar.length) parts.push(related("Looks like", subject.visually_similar, open));
  if (subject.found_in.length) {
    parts.push(related(subject.type === "radical" ? "Found in kanji" : "Found in vocabulary", subject.found_in, open));
  }
  return parts;
}

function section(title: string, ...children: Node[]): HTMLElement {
  return el("section", { class: "section" }, el("h2", {}, title), ...children);
}

/** Kanji: one column per reading type, the primary type bold. Vocabulary:
 * the readings in a row, primary first. */
function readings(subject: Subject): HTMLElement {
  if (subject.type !== "kanji") {
    return el("p", { class: "readings-inline", lang: "ja" }, ...subject.readings.map((r) => el("span", { class: r.primary ? "primary" : "" }, r.reading)));
  }
  const byType = (type: Reading["type"]) => subject.readings.filter((r) => r.type === type);
  return el(
    "div",
    { class: "readings" },
    ...(["onyomi", "kunyomi", "nanori"] as const).map((type) => {
      const items = byType(type);
      return el(
        "div",
        { class: items.some((r) => r.primary) ? "primary" : "" },
        el("span", { class: "meta" }, READING_LABEL[type]),
        el("span", { lang: "ja" }, items.length ? items.map((r) => r.reading).join("、") : "—"),
      );
    }),
  );
}

function related(title: string, subjects: SubjectCard[], open: (id: number) => void): HTMLElement {
  const grid = el("div", { class: "grid" });
  const show = (all: boolean) => {
    const shown = all ? subjects : subjects.slice(0, RELATED_LIMIT);
    grid.replaceChildren(...shown.map((subject) => card(subject, () => open(subject.id))));
  };
  show(false);
  const parts: Node[] = [grid];
  if (subjects.length > RELATED_LIMIT) {
    const more = el("button", { class: "more", type: "button" }, `Show all ${plural(subjects.length, "subject")}`);
    more.addEventListener("click", () => {
      show(true);
      more.remove();
    });
    parts.push(more);
  }
  return section(title, ...parts);
}
