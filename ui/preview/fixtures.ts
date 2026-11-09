// Sample tool outputs for the preview page. Characters, meanings, readings
// and levels follow WaniKani; mnemonics, hints and sentences are written for
// this preview, not taken from WaniKani.

import type { FindNewKanjiOutput, FindNewVocabularyOutput, GetSubjectsOutput, ProgressOutput, Subject, SubjectCard } from "../src/output";

const WK = "https://www.wanikani.com";

function kanji(id: number, characters: string, meaning: string, reading: string, level: number, srs_stage: number | null): SubjectCard {
  return { id, type: "kanji", characters, meaning, reading, level, url: `${WK}/kanji/${encodeURIComponent(characters)}`, srs_stage };
}

function vocabulary(id: number, characters: string, meaning: string, reading: string, level: number, srs_stage: number | null): SubjectCard {
  return { id, type: "vocabulary", characters, meaning, reading, level, url: `${WK}/vocabulary/${encodeURIComponent(characters)}`, srs_stage };
}

function radical(id: number, characters: string, meaning: string, level: number, srs_stage: number | null): SubjectCard {
  return { id, type: "radical", characters, meaning, level, url: `${WK}/radicals/${meaning.toLowerCase()}`, srs_stage };
}

const MOUNTAIN_RADICAL = radical(18, "山", "Mountain", 1, 9);
const FIRE_RADICAL = radical(5, "火", "Fire", 1, 9);

const MOUNTAIN: Subject = {
  ...kanji(450, "山", "Mountain", "さん", 1, 9),
  meanings: ["Mountain"],
  readings: [
    { reading: "さん", primary: true, type: "onyomi" },
    { reading: "やま", primary: false, type: "kunyomi" },
  ],
  parts_of_speech: [],
  meaning_mnemonic: "The <radical>mountain</radical> radical and the <kanji>mountain</kanji> kanji look exactly alike, so this one is free.",
  meaning_hint: null,
  reading_mnemonic:
    "Picture three peaks lined up, each one a <reading>さん</reading>. Count them out loud as you climb: one, two, <reading>さん</reading>.",
  reading_hint: "Vocabulary built from this kanji often uses the kun’yomi <ja>やま</ja> instead.",
  components: [MOUNTAIN_RADICAL],
  visually_similar: [kanji(1180, "仙", "Hermit", "せん", 18, null)],
  found_in: [
    vocabulary(2580, "山", "Mountain", "やま", 1, 9),
    vocabulary(2581, "火山", "Volcano", "かざん", 2, 8),
    vocabulary(3620, "富士山", "Mt Fuji", "ふじさん", 4, 7),
    vocabulary(2820, "山道", "Mountain Road", "やまみち", 3, 6),
    vocabulary(5310, "登山", "Mountain Climbing", "とざん", 14, 3),
    vocabulary(2583, "山火事", "Forest Fire", "やまかじ", 5, 5),
    vocabulary(7720, "山脈", "Mountain Range", "さんみゃく", 30, null),
    vocabulary(4410, "山場", "Climax", "やまば", 9, 2),
    vocabulary(6110, "沢山", "A Lot", "たくさん", 21, 1),
    vocabulary(8020, "山腹", "Hillside", "さんぷく", 40, null),
  ],
  context_sentences: [],
};

const FIRE: Subject = {
  ...kanji(451, "火", "Fire", "か", 1, 6),
  meanings: ["Fire"],
  readings: [
    { reading: "か", primary: true, type: "onyomi" },
    { reading: "ひ", primary: false, type: "kunyomi" },
    { reading: "ほ", primary: false, type: "kunyomi" },
  ],
  parts_of_speech: [],
  meaning_mnemonic: "Same shape as the <radical>fire</radical> radical, same meaning: <kanji>fire</kanji>.",
  meaning_hint: null,
  reading_mnemonic: "A campfire crackles: <reading>か</reading>, <reading>か</reading>, <reading>か</reading>.",
  reading_hint: null,
  components: [FIRE_RADICAL],
  visually_similar: [],
  found_in: [vocabulary(2581, "火山", "Volcano", "かざん", 2, 8), vocabulary(2583, "山火事", "Forest Fire", "やまかじ", 5, 5)],
  context_sentences: [],
};

const VOLCANO: Subject = {
  ...vocabulary(2581, "火山", "Volcano", "かざん", 2, 8),
  meanings: ["Volcano"],
  readings: [{ reading: "かざん", primary: true }],
  parts_of_speech: ["Noun"],
  meaning_mnemonic: "A <kanji>fire</kanji> <kanji>mountain</kanji> is a <vocabulary>volcano</vocabulary>.",
  meaning_hint: "Picture the top of the mountain glowing orange.",
  reading_mnemonic:
    "Both kanji use their on’yomi here: <reading>か</reading> from fire and <reading>ざん</reading> from mountain, voiced because it follows another sound.",
  reading_hint: null,
  components: [MOUNTAIN, FIRE].map(({ id, type, characters, meaning, reading, level, url, srs_stage }) => ({ id, type, characters, meaning, reading, level, url, srs_stage })),
  visually_similar: [],
  found_in: [],
  context_sentences: [
    { ja: "あの火山はまだ生きています。", en: "That volcano is still active." },
    { ja: "火山の近くに温泉があります。", en: "There are hot springs near the volcano." },
  ],
};

export const SUBJECTS: Record<number, Subject> = { [MOUNTAIN.id]: MOUNTAIN, [FIRE.id]: FIRE, [VOLCANO.id]: VOLCANO };

/** get_kanji_by_character for 山 and 火, and one WaniKani does not teach. */
export const GET_KANJI: GetSubjectsOutput = { subjects: [MOUNTAIN, FIRE], not_found: ["丼"] };

export const GET_VOCABULARY: GetSubjectsOutput = { subjects: [VOLCANO], not_found: [] };

export const FIND_NEW_KANJI: FindNewKanjiOutput = {
  sentence: "週末に友達と富士山に登って、頂上で日の出を見ました。",
  subjects: [
    kanji(1043, "頂", "Summit", "ちょう", 19, null),
    kanji(1520, "登", "Climb", "と", 14, 0),
    kanji(712, "週", "Week", "しゅう", 9, null),
    kanji(870, "末", "End", "まつ", 11, null),
    kanji(1610, "富", "Wealth", "ふ", 14, null),
  ].sort((a, b) => a.level - b.level),
};

export const FIND_NEW_VOCABULARY: FindNewVocabularyOutput = {
  phrases: ["登山", "頂上", "日の出", "週末", "山小屋"],
  subjects: [
    vocabulary(5310, "登山", "Mountain Climbing", "とざん", 14, 3),
    vocabulary(5880, "頂上", "Summit", "ちょうじょう", 19, null),
    vocabulary(3770, "日の出", "Sunrise", "ひので", 7, 4),
    vocabulary(4120, "週末", "Weekend", "しゅうまつ", 11, null),
  ],
  not_found: ["山小屋"],
};

const LEVEL_12: SubjectCard[] = [
  radical(301, "疋", "Coat Rack", 12, 6),
  radical(302, "隹", "Turkey", 12, 5),
  radical(303, "曷", "Wolf", 12, 4),
  radical(304, "癶", "Tent", 12, 2),
  kanji(1301, "悪", "Bad", "あく", 12, 5),
  kanji(1302, "暗", "Dark", "あん", 12, 5),
  kanji(1303, "医", "Medicine", "い", 12, 6),
  kanji(1304, "意", "Idea", "い", 12, 5),
  kanji(1305, "感", "Feeling", "かん", 12, 4),
  kanji(1306, "暑", "Hot", "しょ", 12, 3),
  kanji(1307, "温", "Warm", "おん", 12, 3),
  kanji(1308, "員", "Member", "いん", 12, 2),
  kanji(1309, "運", "Carry", "うん", 12, 2),
  kanji(1310, "息", "Breath", "そく", 12, 1),
  kanji(1311, "階", "Floor", "かい", 12, 1),
  kanji(1312, "寒", "Cold", "かん", 12, 0),
  kanji(1313, "期", "Period", "き", 12, null),
  kanji(1314, "号", "Number", "ごう", 12, null),
  kanji(1315, "歯", "Tooth", "し", 12, null),
  kanji(1316, "想", "Concept", "そう", 12, null),
  kanji(1317, "遠", "Far", "えん", 12, null),
  kanji(1318, "葉", "Leaf", "よう", 12, null),
];

function hoursFromNow(hours: number): string {
  const at = new Date();
  at.setMinutes(0, 0, 0);
  at.setHours(at.getHours() + hours);
  return at.toISOString();
}

export const PROGRESS: ProgressOutput = {
  username: "koichi_fan",
  level: 12,
  max_level: 60,
  level_started_at: new Date(Date.now() - 6 * 86_400_000).toISOString(),
  level_kanji: { passed: 4, total: 18 },
  level_radicals: { passed: 2, total: 4 },
  level_subjects: LEVEL_12,
  srs: { apprentice: 87, guru: 214, master: 160, enlightened: 301, burned: 412 },
  lessons_available: 15,
  reviews_available: 42,
  forecast: [
    { at: hoursFromNow(1), reviews: 6 },
    { at: hoursFromNow(2), reviews: 14 },
    { at: hoursFromNow(4), reviews: 3 },
    { at: hoursFromNow(7), reviews: 22 },
    { at: hoursFromNow(9), reviews: 9 },
    { at: hoursFromNow(13), reviews: 31 },
    { at: hoursFromNow(18), reviews: 5 },
    { at: hoursFromNow(22), reviews: 12 },
  ],
};
