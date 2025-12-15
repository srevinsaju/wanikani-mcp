use std::collections::HashMap;
use crate::error::Error;
use crate::result::Result;
use crate::wanikani::WanikaniInner;
use rmcp::model::CallToolResult;
use rmcp::model::Content;
use serde::{Deserialize, Serialize};
use wanisabi::model::subject::Subject;
use wanisabi::wrapper::subject::SubjectFilter;
use wana_kana::IsJapaneseChar;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearntKanjiItem {
    pub character: String,
    pub level: i64,
    pub radicals: Vec<String>
}

impl From<LearntKanjiItem> for Content {
    fn from(item: LearntKanjiItem) -> Self {
        Content::json(item).unwrap()
    }
}

impl WanikaniInner {
    pub async fn get_subject(&self, subject_id: i64) -> Result<CallToolResult> {
        let subject = self.client.get_subject(subject_id).await?;

        if let Subject::Kanji(kanji) = &subject.data {
            return Ok(CallToolResult::success(vec![Content::json(&subject)?]));
        }

        Err(Error::NotFound(format!(
            "Kanji with subject id '{}' not found",
            subject_id
        )))
    }

    pub async fn get_kanji_by_character(&self, characters: Vec<String>) -> Result<CallToolResult> {
        let subjects = self
            .client
            .get_subjects_filtered(vec![
                SubjectFilter::Types(vec!["kanji".to_string()]),
                SubjectFilter::Slugs(characters.to_vec()),
            ])
            .await?;

        let mut results = Vec::new();

        for subject in subjects.data {
            if let Subject::Kanji(kanji) = &subject.data
                && characters.contains(&kanji.characters)
            {
                results.push(Content::json(&subject)?);
            }
        }
        if !results.is_empty() {
            return Ok(CallToolResult::success(results));
        }
        Err(Error::NotFound(format!(
            "Kanji characters '{:?}' not found",
            characters
        )))
    }

    pub async fn get_vocabulary_by_phrase(&self, phrase: String) -> Result<CallToolResult> {
        let subjects = self
            .client
            .get_subjects_filtered(vec![
                SubjectFilter::Types(vec!["vocabulary".to_string()]),
                SubjectFilter::Slugs(vec![phrase.clone()]),
            ])
            .await?;

        for subject in subjects.data {
            if let Subject::Vocabulary(vocab) = &subject.data
                && vocab.slug == phrase
            {
                return Ok(CallToolResult::success(vec![Content::json(&subject)?]));
            }
        }
        Err(Error::NotFound(format!(
            "Vocabulary phrase '{}' not found",
            phrase
        )))
    }

    pub async fn find_new_kanji_from_sentence(&self, sentence: String) -> Result<CallToolResult> {
        let chars: Vec<String> = sentence.chars().map(|c| c.to_string()).collect();
        // filter chars by single kanji characters, not hiragana, katakana, or others
        let chars: Vec<String> = chars
            .into_iter()
            .filter(|c| c.chars().all(|ch| ch.is_kanji()))
            .collect();

        if chars.is_empty() {
            return Err(Error::InvalidArgument(
                "No kanji characters found in the given sentence".to_string(),
            ));
        }

        let mut found_subjects = Vec::new();
        let user = self.client.get_user_info().await?;
        let user_level = user.data.level;



        let kanji_subjects = self
            .client
            .get_subjects_filtered(vec![
                SubjectFilter::Types(vec!["kanji".to_string()]),
                SubjectFilter::Slugs(chars.clone()),
                SubjectFilter::Levels((user_level..=60).collect()),
            ])
            .await?;

        let radicals_used_in_kanji = kanji_subjects.data.iter().filter_map(|subject| {
            if let Subject::Kanji(kanji) = &subject.data {
                Some(kanji.amalgamation_subject_ids.clone())
            } else {
                None
            }
        }).flatten().collect::<Vec<i64>>();

        let radicals: HashMap<i64, Vec<String>> = {
            let radical_subjects = self
                .client
                .get_subjects_filtered(vec![
                    SubjectFilter::Types(vec!["radical".to_string()]),
                    SubjectFilter::Ids(radicals_used_in_kanji.clone()),
                ])
                .await?;
            let mut map = HashMap::new();
            for subject in radical_subjects.data {
                if let Subject::Radical(radical) = &subject.data {
                    map.insert(subject.id, radical.meanings.iter().map(|m| m.meaning.clone()).collect());
                }
            }
            map
        };

        for subject in kanji_subjects.data {
            if let Subject::Kanji(kanji) = &subject.data
                && chars.contains(&kanji.characters)
            {
                found_subjects.push(LearntKanjiItem {
                    character: kanji.characters.clone(),
                    level: kanji.level,
                    radicals: kanji.amalgamation_subject_ids.iter().filter_map(|id| radicals.get(id)).flatten().cloned().collect(),
                });
            }
        }

        if !found_subjects.is_empty() {
            return Ok(CallToolResult::success(
                found_subjects.into_iter().map(|item| item.into()).collect(),
            ));
        }

        Err(Error::NotFound(format!(
            "No new kanji found in sentence '{}'",
            sentence
        )))
    }

    pub async fn find_new_vocabulary(&self, phrases: Vec<String>) -> Result<CallToolResult> {
        let user = self.client.get_user_info().await?;
        let user_level = user.data.level;

        let vocabulary_subjects = self
            .client
            .get_subjects_filtered(vec![
                SubjectFilter::Types(vec!["vocabulary".to_string()]),
                SubjectFilter::Slugs(phrases.clone()),
                SubjectFilter::Levels((user_level..=60).collect()),
            ])
            .await?;

        let mut found_subjects = Vec::new();

        for subject in vocabulary_subjects.data {
            if let Subject::Vocabulary(vocab) = &subject.data
                && phrases.contains(&vocab.slug)
            {
                found_subjects.push(Content::json(&subject)?);
            }
        }

        if !found_subjects.is_empty() {
            return Ok(CallToolResult::success(found_subjects));
        }

        Err(Error::NotFound("No new vocabulary found".to_string()))
    }
}
