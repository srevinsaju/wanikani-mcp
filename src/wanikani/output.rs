//! The `structuredContent` of every tool, as declared by its `outputSchema`.
//! Mirrors [ui/src/output.ts](../../ui/src/output.ts), which the views
//! render; a change here is a change there.
//!
//! Each output also renders a short text, for hosts without MCP Apps.

use std::collections::HashMap;
use std::fmt::Write;

use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};
use wanisabi::model::subject::{
    ReadingType as WanikaniReadingType, Sentence, Subject as WanikaniSubject,
};
use wanisabi::response::IdResponse;

/// What a tool returns: structured content matching its `outputSchema`, and a
/// text rendering that stands on its own for hosts without MCP Apps.
pub trait Output: Serialize + JsonSchema {
    fn summary(&self) -> String;
}

pub fn reply(output: impl Output) -> CallToolResult {
    let summary = output.summary();
    let mut result = CallToolResult::structured(serde_json::to_value(output).unwrap());
    result.content = vec![ContentBlock::text(summary)];
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SubjectType {
    Radical,
    Kanji,
    Vocabulary,
    KanaVocabulary,
}

/// Enough of a subject to draw its tile.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SubjectCard {
    pub id: i64,
    #[serde(rename = "type")]
    pub subject_type: SubjectType,
    /// Null for radicals that only have an image.
    pub characters: Option<String>,
    /// An SVG on files.wanikani.com, for radicals without characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub character_image: Option<String>,
    /// The primary meaning.
    pub meaning: String,
    /// The primary reading. Radicals have none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reading: Option<String>,
    pub level: i64,
    /// The subject's page on wanikani.com.
    pub url: String,
    /// WaniKani's SRS stage: 0 is a lesson not yet taken, 1–4 Apprentice, 5–6
    /// Guru, 7 Master, 8 Enlightened, 9 Burned. Null when the subject is locked.
    pub srs_stage: Option<i64>,
}

impl SubjectCard {
    /// `srs_stage` is the stage of the user's assignment for this subject, or
    /// `None` when they have none because it is locked.
    pub fn new(subject: &IdResponse<WanikaniSubject>, srs_stage: Option<i64>) -> Self {
        let (subject_type, characters, character_image, meanings, reading, level, url) =
            match &subject.data {
                WanikaniSubject::Radical(radical) => (
                    SubjectType::Radical,
                    radical.characters.clone(),
                    match radical.characters {
                        Some(_) => None,
                        None => radical
                            .character_images
                            .iter()
                            .find(|image| image.content_type == "image/svg+xml")
                            .map(|image| image.url.clone()),
                    },
                    &radical.meanings,
                    None,
                    radical.level,
                    &radical.document_url,
                ),
                WanikaniSubject::Kanji(kanji) => (
                    SubjectType::Kanji,
                    Some(kanji.characters.clone()),
                    None,
                    &kanji.meanings,
                    kanji
                        .readings
                        .iter()
                        .find(|reading| reading.primary)
                        .map(|reading| reading.reading.clone()),
                    kanji.level,
                    &kanji.document_url,
                ),
                WanikaniSubject::Vocabulary(vocabulary) => (
                    SubjectType::Vocabulary,
                    Some(vocabulary.characters.clone()),
                    None,
                    &vocabulary.meanings,
                    vocabulary
                        .readings
                        .iter()
                        .find(|reading| reading.primary)
                        .map(|reading| reading.reading.clone()),
                    vocabulary.level,
                    &vocabulary.document_url,
                ),
                WanikaniSubject::KanaVocabulary(vocabulary) => (
                    SubjectType::KanaVocabulary,
                    Some(vocabulary.characters.clone()),
                    None,
                    &vocabulary.meanings,
                    None,
                    vocabulary.level,
                    &vocabulary.document_url,
                ),
            };
        let meaning = meanings
            .iter()
            .find(|meaning| meaning.primary)
            .expect("WaniKani gives every subject a primary meaning")
            .meaning
            .clone();
        Self {
            id: subject.id,
            subject_type,
            characters,
            character_image,
            meaning,
            reading,
            level,
            url: url.clone(),
            srs_stage,
        }
    }

    /// `山 (kanji, level 1, Guru I)`: the subject on one line.
    fn line(&self) -> String {
        let name = self.characters.as_deref().unwrap_or(&self.meaning);
        let mut line = format!("{name} — {}", self.meaning);
        if let Some(reading) = &self.reading {
            write!(line, " ({reading})").unwrap();
        }
        write!(
            line,
            ", {} level {}, {}",
            self.subject_type.label(),
            self.level,
            srs_stage_name(self.srs_stage)
        )
        .unwrap();
        line
    }
}

impl SubjectType {
    fn label(self) -> &'static str {
        match self {
            SubjectType::Radical => "radical",
            SubjectType::Kanji => "kanji",
            SubjectType::Vocabulary => "vocabulary",
            SubjectType::KanaVocabulary => "kana vocabulary",
        }
    }
}

/// The SRS stage as WaniKani names it.
fn srs_stage_name(srs_stage: Option<i64>) -> &'static str {
    match srs_stage {
        None => "locked",
        Some(0) => "lesson",
        Some(1) => "Apprentice I",
        Some(2) => "Apprentice II",
        Some(3) => "Apprentice III",
        Some(4) => "Apprentice IV",
        Some(5) => "Guru I",
        Some(6) => "Guru II",
        Some(7) => "Master",
        Some(8) => "Enlightened",
        Some(9) => "Burned",
        Some(stage) => panic!("WaniKani has no SRS stage {stage}"),
    }
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReadingType {
    Onyomi,
    Kunyomi,
    Nanori,
}

impl From<&WanikaniReadingType> for ReadingType {
    fn from(reading_type: &WanikaniReadingType) -> Self {
        match reading_type {
            WanikaniReadingType::Onyomi => ReadingType::Onyomi,
            WanikaniReadingType::Kunyomi => ReadingType::Kunyomi,
            WanikaniReadingType::Nanori => ReadingType::Nanori,
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Reading {
    pub reading: String,
    pub primary: bool,
    /// Kanji only.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub reading_type: Option<ReadingType>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ContextSentence {
    pub ja: String,
    pub en: String,
}

/// A subject with everything its page shows. Mnemonics and hints keep
/// WaniKani's markup: `<radical>`, `<kanji>`, `<vocabulary>`, `<reading>`,
/// `<meaning>` and `<ja>`.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Subject {
    #[serde(flatten)]
    pub card: SubjectCard,
    /// Every accepted meaning, primary first.
    pub meanings: Vec<String>,
    pub readings: Vec<Reading>,
    pub parts_of_speech: Vec<String>,
    pub meaning_mnemonic: String,
    pub meaning_hint: Option<String>,
    pub reading_mnemonic: Option<String>,
    pub reading_hint: Option<String>,
    /// Radicals in a kanji, or kanji in a vocabulary word.
    pub components: Vec<SubjectCard>,
    /// Kanji only.
    pub visually_similar: Vec<SubjectCard>,
    /// Kanji a radical is in, or vocabulary a kanji is in.
    pub found_in: Vec<SubjectCard>,
    pub context_sentences: Vec<ContextSentence>,
}

/// The subjects a subject's page links to: components, visually similar
/// kanji, and what it is found in.
pub fn related_subject_ids(subject: &WanikaniSubject) -> Vec<i64> {
    match subject {
        WanikaniSubject::Radical(radical) => radical.amalgamation_subject_ids.clone(),
        WanikaniSubject::Kanji(kanji) => [
            &kanji.component_subject_ids,
            &kanji.visually_similar_subject_ids,
            &kanji.amalgamation_subject_ids,
        ]
        .into_iter()
        .flatten()
        .copied()
        .collect(),
        WanikaniSubject::Vocabulary(vocabulary) => vocabulary.component_subject_ids.clone(),
        WanikaniSubject::KanaVocabulary(_) => Vec::new(),
    }
}

impl Subject {
    /// `related` holds a card for every id [`related_subject_ids`] gives.
    pub fn new(
        subject: &IdResponse<WanikaniSubject>,
        srs_stage: Option<i64>,
        related: &HashMap<i64, SubjectCard>,
    ) -> Self {
        let cards = |ids: &[i64]| ids.iter().map(|id| related[id].clone()).collect();
        let card = SubjectCard::new(subject, srs_stage);
        match &subject.data {
            WanikaniSubject::Radical(radical) => Self {
                card,
                meanings: accepted_meanings(&radical.meanings),
                readings: Vec::new(),
                parts_of_speech: Vec::new(),
                meaning_mnemonic: radical.meaning_mnemonic.clone(),
                meaning_hint: None,
                reading_mnemonic: None,
                reading_hint: None,
                components: Vec::new(),
                visually_similar: Vec::new(),
                found_in: cards(&radical.amalgamation_subject_ids),
                context_sentences: Vec::new(),
            },
            WanikaniSubject::Kanji(kanji) => Self {
                card,
                meanings: accepted_meanings(&kanji.meanings),
                readings: kanji
                    .readings
                    .iter()
                    .map(|reading| Reading {
                        reading: reading.reading.clone(),
                        primary: reading.primary,
                        reading_type: Some((&reading.kind).into()),
                    })
                    .collect(),
                parts_of_speech: Vec::new(),
                meaning_mnemonic: kanji.meaning_mnemonic.clone(),
                meaning_hint: kanji.meaning_hint.clone(),
                reading_mnemonic: Some(kanji.reading_mnemonic.clone()),
                reading_hint: kanji.reading_hint.clone(),
                components: cards(&kanji.component_subject_ids),
                visually_similar: cards(&kanji.visually_similar_subject_ids),
                found_in: cards(&kanji.amalgamation_subject_ids),
                context_sentences: Vec::new(),
            },
            WanikaniSubject::Vocabulary(vocabulary) => Self {
                card,
                meanings: accepted_meanings(&vocabulary.meanings),
                readings: vocabulary
                    .readings
                    .iter()
                    .map(|reading| Reading {
                        reading: reading.reading.clone(),
                        primary: reading.primary,
                        reading_type: None,
                    })
                    .collect(),
                parts_of_speech: vocabulary.parts_of_speech.clone(),
                meaning_mnemonic: vocabulary.meaning_mnemonic.clone(),
                meaning_hint: None,
                reading_mnemonic: Some(vocabulary.reading_mnemonic.clone()),
                reading_hint: None,
                components: cards(&vocabulary.component_subject_ids),
                visually_similar: Vec::new(),
                found_in: Vec::new(),
                context_sentences: context_sentences(&vocabulary.context_sentences),
            },
            WanikaniSubject::KanaVocabulary(vocabulary) => Self {
                card,
                meanings: accepted_meanings(&vocabulary.meanings),
                readings: Vec::new(),
                parts_of_speech: vocabulary.parts_of_speech.clone(),
                meaning_mnemonic: vocabulary.meaning_mnemonic.clone(),
                meaning_hint: None,
                reading_mnemonic: None,
                reading_hint: None,
                components: Vec::new(),
                visually_similar: Vec::new(),
                found_in: Vec::new(),
                context_sentences: context_sentences(&vocabulary.context_sentences),
            },
        }
    }

    fn summary(&self) -> String {
        let mut text = self.card.line();
        write!(text, "\nMeanings: {}", self.meanings.join(", ")).unwrap();
        if !self.readings.is_empty() {
            let readings: Vec<&str> = self.readings.iter().map(|r| r.reading.as_str()).collect();
            write!(text, "\nReadings: {}", readings.join(", ")).unwrap();
        }
        if !self.components.is_empty() {
            let components: Vec<String> = self
                .components
                .iter()
                .map(|card| match &card.characters {
                    Some(characters) => format!("{characters} ({})", card.meaning),
                    None => card.meaning.clone(),
                })
                .collect();
            write!(text, "\nComponents: {}", components.join(", ")).unwrap();
        }
        write!(text, "\nMeaning mnemonic: {}", self.meaning_mnemonic).unwrap();
        if let Some(reading_mnemonic) = &self.reading_mnemonic {
            write!(text, "\nReading mnemonic: {reading_mnemonic}").unwrap();
        }
        text
    }
}

/// Every accepted meaning, primary first.
fn accepted_meanings(meanings: &[wanisabi::model::subject::Meaning]) -> Vec<String> {
    let mut accepted: Vec<_> = meanings
        .iter()
        .filter(|meaning| meaning.accepted_answer)
        .collect();
    accepted.sort_by_key(|meaning| !meaning.primary);
    accepted
        .into_iter()
        .map(|meaning| meaning.meaning.clone())
        .collect()
}

/// wanisabi keeps [`Sentence`]'s fields private; its serde form is WaniKani's
/// `{"en", "ja"}`, so read them through that.
fn context_sentences(sentences: &[Sentence]) -> Vec<ContextSentence> {
    serde_json::from_value(serde_json::to_value(sentences).unwrap()).unwrap()
}

/// get_subject_by_id, get_kanji_by_character and get_vocabulary_by_phrase.
#[derive(Debug, Serialize, JsonSchema)]
pub struct GetSubjectsOutput {
    pub subjects: Vec<Subject>,
    /// Characters or phrases asked for that WaniKani does not teach.
    pub not_found: Vec<String>,
}

impl Output for GetSubjectsOutput {
    fn summary(&self) -> String {
        let mut blocks: Vec<String> = self.subjects.iter().map(Subject::summary).collect();
        if !self.not_found.is_empty() {
            blocks.push(format!("Not on WaniKani: {}", self.not_found.join(", ")));
        }
        blocks.join("\n\n")
    }
}

/// find_new_kanji_from_sentence.
#[derive(Debug, Serialize, JsonSchema)]
pub struct FindNewKanjiOutput {
    pub sentence: String,
    pub subjects: Vec<SubjectCard>,
}

impl Output for FindNewKanjiOutput {
    fn summary(&self) -> String {
        if self.subjects.is_empty() {
            return format!("No new kanji in {:?}.", self.sentence);
        }
        cards_summary(format!("New kanji in {:?}:", self.sentence), &self.subjects)
    }
}

/// find_new_vocabulary.
#[derive(Debug, Serialize, JsonSchema)]
pub struct FindNewVocabularyOutput {
    pub phrases: Vec<String>,
    pub subjects: Vec<SubjectCard>,
    pub not_found: Vec<String>,
}

impl Output for FindNewVocabularyOutput {
    fn summary(&self) -> String {
        let mut text = if self.subjects.is_empty() {
            "No new vocabulary.".to_owned()
        } else {
            cards_summary("New vocabulary:".to_owned(), &self.subjects)
        };
        if !self.not_found.is_empty() {
            write!(text, "\nNot on WaniKani: {}", self.not_found.join(", ")).unwrap();
        }
        text
    }
}

fn cards_summary(heading: String, cards: &[SubjectCard]) -> String {
    let mut text = heading;
    for card in cards {
        write!(text, "\n- {}", card.line()).unwrap();
    }
    text
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PassedCount {
    pub passed: usize,
    pub total: usize,
}

/// Assignments per SRS group, across all levels.
#[derive(Debug, Serialize, JsonSchema)]
pub struct SrsCounts {
    pub apprentice: i64,
    pub guru: i64,
    pub master: i64,
    pub enlightened: i64,
    pub burned: i64,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ForecastHour {
    /// The hour, RFC 3339.
    pub at: String,
    pub reviews: usize,
}

/// get_level_info.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ProgressOutput {
    pub username: String,
    pub level: i64,
    /// The highest level the subscription allows.
    pub max_level: i64,
    /// When the current level was unlocked, RFC 3339.
    pub level_started_at: Option<String>,
    /// Kanji passed (Guru or above) on the current level; 90% levels up.
    pub level_kanji: PassedCount,
    pub level_radicals: PassedCount,
    /// The current level's subjects, so the view can draw them by stage.
    pub level_subjects: Vec<SubjectCard>,
    pub srs: SrsCounts,
    pub lessons_available: usize,
    pub reviews_available: usize,
    /// Reviews coming up, one entry per hour that has any, for the next 24 hours.
    pub forecast: Vec<ForecastHour>,
}

impl Output for ProgressOutput {
    fn summary(&self) -> String {
        let upcoming: usize = self.forecast.iter().map(|hour| hour.reviews).sum();
        let SrsCounts {
            apprentice,
            guru,
            master,
            enlightened,
            burned,
        } = self.srs;
        format!(
            "{} is on level {} of {}.\n\
             Lessons available: {}. Reviews available: {}. Reviews in the next 24 hours: {upcoming}.\n\
             This level: {}/{} kanji and {}/{} radicals passed.\n\
             SRS: {apprentice} apprentice, {guru} guru, {master} master, {enlightened} enlightened, {burned} burned.",
            self.username,
            self.level,
            self.max_level,
            self.lessons_available,
            self.reviews_available,
            self.level_kanji.passed,
            self.level_kanji.total,
            self.level_radicals.passed,
            self.level_radicals.total,
        )
    }
}
