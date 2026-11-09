// The structuredContent of the tools that show a view. Proposed: the Rust
// tools do not return these yet. Once they do, their outputSchema is
// authoritative and this file mirrors it.

export type SubjectType = "radical" | "kanji" | "vocabulary" | "kana_vocabulary";

/** WaniKani's SRS stage: 0 is a lesson not yet taken, 1–4 Apprentice, 5–6
 * Guru, 7 Master, 8 Enlightened, 9 Burned. Null when the subject is locked. */
export type SrsStage = number | null;

/** Enough of a subject to draw its tile. */
export interface SubjectCard {
  id: number;
  type: SubjectType;
  /** Null for radicals that only have an image. */
  characters: string | null;
  /** An SVG on files.wanikani.com, for radicals without characters. */
  character_image?: string;
  /** The primary meaning. */
  meaning: string;
  /** The primary reading. Radicals have none. */
  reading?: string;
  level: number;
  /** The subject's page on wanikani.com. */
  url: string;
  srs_stage: SrsStage;
}

export interface Reading {
  reading: string;
  primary: boolean;
  /** Kanji only. */
  type?: "onyomi" | "kunyomi" | "nanori";
}

/** Mnemonics and hints keep WaniKani's markup: `<radical>`, `<kanji>`,
 * `<vocabulary>`, `<reading>`, `<meaning>` and `<ja>`. The view draws them as
 * highlights and never parses anything else as HTML. */
export type Markup = string;

export interface Subject extends SubjectCard {
  /** Every accepted meaning, primary first. */
  meanings: string[];
  readings: Reading[];
  parts_of_speech: string[];
  meaning_mnemonic: Markup;
  meaning_hint: Markup | null;
  reading_mnemonic: Markup | null;
  reading_hint: Markup | null;
  /** Radicals in a kanji, or kanji in a vocabulary word. */
  components: SubjectCard[];
  /** Kanji only. */
  visually_similar: SubjectCard[];
  /** Kanji a radical is in, or vocabulary a kanji is in. */
  found_in: SubjectCard[];
  context_sentences: { ja: string; en: string }[];
}

/** get_subject_by_id, get_kanji_by_character and get_vocabulary_by_phrase. */
export interface GetSubjectsOutput {
  subjects: Subject[];
  /** Characters or phrases asked for that WaniKani does not teach. */
  not_found: string[];
}

/** find_new_kanji_from_sentence. */
export interface FindNewKanjiOutput {
  sentence: string;
  subjects: SubjectCard[];
}

/** find_new_vocabulary. */
export interface FindNewVocabularyOutput {
  phrases: string[];
  subjects: SubjectCard[];
  not_found: string[];
}

export type SubjectsOutput = FindNewKanjiOutput | FindNewVocabularyOutput;

export type SrsGroup = "apprentice" | "guru" | "master" | "enlightened" | "burned";

/** get_level_info. */
export interface ProgressOutput {
  username: string;
  level: number;
  /** The highest level the subscription allows. */
  max_level: number;
  /** When the current level started, RFC 3339. */
  level_started_at: string | null;
  /** Kanji passed (Guru or above) on the current level; 90% levels up. */
  level_kanji: { passed: number; total: number };
  level_radicals: { passed: number; total: number };
  /** The current level's subjects, so the view can draw them by stage. */
  level_subjects: SubjectCard[];
  srs: Record<SrsGroup, number>;
  lessons_available: number;
  reviews_available: number;
  /** Reviews coming up, one entry per hour that has any, for the next 24 hours. */
  forecast: { at: string; reviews: number }[];
}
