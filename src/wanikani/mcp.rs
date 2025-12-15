use crate::wanikani::Wanikani;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::CallToolResult;
use rmcp::{ErrorData as McpError, schemars, tool, tool_router};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct KanjiByCharacterRequest {
    #[schemars(description = "the list of kanji characters to look up")]
    pub characters: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct SubjectRequest {
    #[schemars(description = "the subject id of the kanji to look up")]
    pub subject_id: i64,
}


#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct VocabularyRequest {
    #[schemars(description = "vocabulary phrase or slug to look up")]
    pub phrase: String,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct SentenceRequest {
    #[schemars(description = "the sentence to find new kanji from")]
    pub sentence: String,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct VocabularyListRequest {
    #[schemars(description = "the list of vocabulary phrases or slugs to look up")]
    pub phrases: Vec<String>,
}

#[tool_router(vis = "pub")]
impl Wanikani {
    #[tool(description = "Get level information")]
    async fn get_level_info(&self) -> Result<CallToolResult, McpError> {
        self.inner.get_level_info().await.map_err(Into::into)
    }

    #[tool(description = "Get subject by its subject id. A subject is a i64 identifier which can be used for kanji, radicals or vocabulary")]
    async fn get_subject_by_id(
        &self,
        Parameters(SubjectRequest { subject_id }): Parameters<SubjectRequest>,
    ) -> Result<CallToolResult, McpError> {
        self.inner
            .get_subject(subject_id)
            .await
            .map_err(Into::into)
    }

    #[tool(description = "Get multiple kanji subjects by its characters. Returns the level, onyomi, kunyomi, reading mnemonic and meaning mnemonics, and radicals that compose the kanji")]
    async fn get_kanji_by_character(
        &self,
        Parameters(KanjiByCharacterRequest { characters }): Parameters<KanjiByCharacterRequest>,
    ) -> Result<CallToolResult, McpError> {
        self.inner
            .get_kanji_by_character(characters)
            .await
            .map_err(Into::into)
    }

    #[tool(description = "Get vocabulary subject by its phrase. Returns the readings, meaning mnemonics and example sentences, and kanji subject IDs that compose the vocabulary")]
    async fn get_vocabulary_by_phrase(
        &self,
        Parameters(VocabularyRequest { phrase }): Parameters<VocabularyRequest>,
    ) -> Result<CallToolResult, McpError> {
        self.inner
            .get_vocabulary_by_phrase(phrase)
            .await
            .map_err(Into::into)
    }

    #[tool(description = "Find new kanji and their wanikani levels from a given sentence that the user has not learned yet")]
    async fn find_new_kanji_from_sentence(
        &self,
        Parameters(SentenceRequest { sentence }): Parameters<SentenceRequest>,
    ) -> Result<CallToolResult, McpError> {
        self.inner
            .find_new_kanji_from_sentence(sentence)
            .await
            .map_err(Into::into)
    }

    #[tool(description = "Find new vocabulary and their wanikani levels from a list of words/phrases that the user has not learned yet")]
    async fn find_new_vocabulary(
        &self,
        Parameters(VocabularyListRequest { phrases }): Parameters<VocabularyListRequest>,
    ) -> Result<CallToolResult, McpError> {
        self.inner
            .find_new_vocabulary(phrases)
            .await
            .map_err(Into::into)
    }
}
