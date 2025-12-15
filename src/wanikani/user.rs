use crate::result::Result;
use crate::wanikani::WanikaniInner;
use rmcp::model::CallToolResult;
use rmcp::model::Content;

impl WanikaniInner {
    pub async fn get_level_info(&self) -> Result<CallToolResult> {
        let user = self.client.get_user_info().await?;

        let level = user.data.level;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Current level: {}",
            level
        ))]))
    }
}
