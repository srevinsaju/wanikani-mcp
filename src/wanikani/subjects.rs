use crate::Error;
use crate::Result;
use crate::wanikani::WanikaniInner;
use crate::wanikani::output::{
    FindNewKanjiOutput, FindNewVocabularyOutput, GetSubjectsOutput, Subject, SubjectCard,
    related_subject_ids,
};
use std::collections::{BTreeSet, HashMap};
use wana_kana::IsJapaneseChar;
use wanisabi::model::subject::Subject as WanikaniSubject;
use wanisabi::response::IdResponse;
use wanisabi::wrapper::subject::SubjectFilter;

/// The types a vocabulary phrase may be.
fn vocabulary_types() -> SubjectFilter {
    SubjectFilter::Types(vec![
        "vocabulary".to_string(),
        "kana_vocabulary".to_string(),
    ])
}

/// The slug WaniKani looks subjects up by: the characters of a kanji, the
/// phrase of a vocabulary word.
fn slug(subject: &WanikaniSubject) -> &str {
    match subject {
        WanikaniSubject::Radical(radical) => &radical.slug,
        WanikaniSubject::Kanji(kanji) => &kanji.slug,
        WanikaniSubject::Vocabulary(vocabulary) => &vocabulary.slug,
        WanikaniSubject::KanaVocabulary(vocabulary) => &vocabulary.slug,
    }
}

fn level(subject: &WanikaniSubject) -> i64 {
    match subject {
        WanikaniSubject::Radical(radical) => radical.level,
        WanikaniSubject::Kanji(kanji) => kanji.level,
        WanikaniSubject::Vocabulary(vocabulary) => vocabulary.level,
        WanikaniSubject::KanaVocabulary(vocabulary) => vocabulary.level,
    }
}

/// `asked`, without the ones a subject's slug matches.
fn not_found(asked: &[String], subjects: &[IdResponse<WanikaniSubject>]) -> Vec<String> {
    asked
        .iter()
        .filter(|asked| !subjects.iter().any(|s| slug(&s.data) == asked.as_str()))
        .cloned()
        .collect()
}

impl WanikaniInner {
    /// Subjects in full, with the cards of the subjects they link to and the
    /// user's SRS stage on each. Two requests, however many subjects.
    async fn subject_details(
        &self,
        subjects: Vec<IdResponse<WanikaniSubject>>,
    ) -> Result<Vec<Subject>> {
        let related_ids: BTreeSet<i64> = subjects
            .iter()
            .flat_map(|subject| related_subject_ids(&subject.data))
            .collect();
        let stage_ids: BTreeSet<i64> = subjects
            .iter()
            .map(|subject| subject.id)
            .chain(related_ids.iter().copied())
            .collect();
        let (related, srs_stages) = tokio::try_join!(
            self.subjects_by_id(&related_ids),
            self.srs_stages(&stage_ids),
        )?;
        let related: HashMap<i64, SubjectCard> = related
            .iter()
            .map(|subject| {
                let card = SubjectCard::new(subject, srs_stages.get(&subject.id).copied());
                (subject.id, card)
            })
            .collect();
        Ok(subjects
            .iter()
            .map(|subject| Subject::new(subject, srs_stages.get(&subject.id).copied(), &related))
            .collect())
    }

    /// Cards for `subjects`, with the user's SRS stage on each.
    async fn subject_cards(
        &self,
        subjects: &[IdResponse<WanikaniSubject>],
    ) -> Result<Vec<SubjectCard>> {
        let ids: BTreeSet<i64> = subjects.iter().map(|subject| subject.id).collect();
        let srs_stages = self.srs_stages(&ids).await?;
        Ok(subjects
            .iter()
            .map(|subject| SubjectCard::new(subject, srs_stages.get(&subject.id).copied()))
            .collect())
    }

    pub async fn get_subject(&self, subject_id: i64) -> Result<GetSubjectsOutput> {
        let subject = self.client.get_subject(subject_id).await?;
        Ok(GetSubjectsOutput {
            subjects: self.subject_details(vec![subject]).await?,
            not_found: Vec::new(),
        })
    }

    /// The kanji WaniKani has; the rest go in `not_found`. Fails only when it
    /// has none of them.
    pub async fn get_kanji_by_character(
        &self,
        characters: Vec<String>,
    ) -> Result<GetSubjectsOutput> {
        let subjects = self
            .subjects(vec![
                SubjectFilter::Types(vec!["kanji".to_string()]),
                SubjectFilter::Slugs(characters.clone()),
            ])
            .await?;
        if subjects.is_empty() {
            return Err(Error::NotFound(format!(
                "Kanji characters '{:?}' not found",
                characters
            )));
        }
        let not_found = not_found(&characters, &subjects);
        Ok(GetSubjectsOutput {
            subjects: self.subject_details(subjects).await?,
            not_found,
        })
    }

    pub async fn get_vocabulary_by_phrase(&self, phrase: String) -> Result<GetSubjectsOutput> {
        let subjects: Vec<_> = self
            .subjects(vec![
                vocabulary_types(),
                SubjectFilter::Slugs(vec![phrase.clone()]),
            ])
            .await?
            .into_iter()
            .filter(|subject| slug(&subject.data) == phrase)
            .collect();
        if subjects.is_empty() {
            return Err(Error::NotFound(format!(
                "Vocabulary phrase '{}' not found",
                phrase
            )));
        }
        Ok(GetSubjectsOutput {
            subjects: self.subject_details(subjects).await?,
            not_found: Vec::new(),
        })
    }

    /// Kanji in `sentence` from the user's level on, in the order they appear.
    pub async fn find_new_kanji_from_sentence(
        &self,
        sentence: String,
    ) -> Result<FindNewKanjiOutput> {
        let mut kanji: Vec<String> = Vec::new();
        for character in sentence.chars().filter(|c| c.is_kanji()) {
            let character = character.to_string();
            if !kanji.contains(&character) {
                kanji.push(character);
            }
        }
        if kanji.is_empty() {
            return Err(Error::InvalidArgument(
                "No kanji characters found in the given sentence".to_string(),
            ));
        }

        let user = self.client.get_user_info().await?;
        let mut subjects = self
            .subjects(vec![
                SubjectFilter::Types(vec!["kanji".to_string()]),
                SubjectFilter::Slugs(kanji.clone()),
                SubjectFilter::Levels((user.data.level..=60).collect()),
            ])
            .await?;
        subjects.sort_by_key(|subject| {
            kanji
                .iter()
                .position(|character| character == slug(&subject.data))
        });

        Ok(FindNewKanjiOutput {
            sentence,
            subjects: self.subject_cards(&subjects).await?,
        })
    }

    /// Vocabulary in `phrases` from the user's level on. Phrases WaniKani does
    /// not teach at any level go in `not_found`.
    pub async fn find_new_vocabulary(
        &self,
        phrases: Vec<String>,
    ) -> Result<FindNewVocabularyOutput> {
        let (user, subjects) = tokio::try_join!(
            async { Ok::<_, Error>(self.client.get_user_info().await?) },
            self.subjects(vec![
                vocabulary_types(),
                SubjectFilter::Slugs(phrases.clone())
            ]),
        )?;
        let not_found = not_found(&phrases, &subjects);
        let mut new: Vec<_> = subjects
            .into_iter()
            .filter(|subject| level(&subject.data) >= user.data.level)
            .collect();
        new.sort_by_key(|subject| {
            phrases
                .iter()
                .position(|phrase| phrase == slug(&subject.data))
        });

        Ok(FindNewVocabularyOutput {
            subjects: self.subject_cards(&new).await?,
            phrases,
            not_found,
        })
    }
}
