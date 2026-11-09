use crate::Error;
use crate::Result;
use crate::wanikani::WanikaniInner;
use crate::wanikani::output::{ForecastHour, PassedCount, ProgressOutput, SrsCounts, SubjectCard};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use wanisabi::model::subject::Subject;
use wanisabi::wrapper::assignments::AssignmentsFilter;
use wanisabi::wrapper::subject::SubjectFilter;

impl WanikaniInner {
    /// The user's assignments in these SRS stages, across all levels.
    async fn srs_count(&self, srs_stages: Vec<i64>) -> Result<i64> {
        let first = self
            .client
            .get_assignments_filtered(vec![
                AssignmentsFilter::SrsStages(srs_stages),
                AssignmentsFilter::Hidden(false),
            ])
            .await?;
        Ok(first.total_count)
    }

    async fn srs_counts(&self) -> Result<SrsCounts> {
        let (apprentice, guru, master, enlightened, burned) = tokio::try_join!(
            self.srs_count(vec![1, 2, 3, 4]),
            self.srs_count(vec![5, 6]),
            self.srs_count(vec![7]),
            self.srs_count(vec![8]),
            self.srs_count(vec![9]),
        )?;
        Ok(SrsCounts {
            apprentice,
            guru,
            master,
            enlightened,
            burned,
        })
    }

    pub async fn get_level_info(&self) -> Result<ProgressOutput> {
        let user = self.client.get_user_info().await?.data;
        let level = user.level;

        let (summary, level_subjects, level_assignments, level_progressions, srs) = tokio::try_join!(
            async { Ok::<_, Error>(self.client.get_summary().await?.data) },
            self.subjects(vec![
                SubjectFilter::Levels(vec![level]),
                SubjectFilter::Hidden(false),
            ]),
            async {
                let first = self
                    .client
                    .get_assignments_filtered(vec![AssignmentsFilter::Levels(vec![level])])
                    .await?;
                self.all_pages(first).await
            },
            async {
                let first = self.client.get_level_progressions().await?;
                self.all_pages(first).await
            },
            self.srs_counts(),
        )?;

        let assignments: HashMap<i64, _> = level_assignments
            .into_iter()
            .map(|assignment| (assignment.data.subject_id, assignment.data))
            .collect();
        // Passed is Guru once, which is what levels up; `passed_at` stays set
        // if the subject later drops back to Apprentice.
        let passed_count = |is_type: fn(&Subject) -> bool| {
            let subjects = level_subjects
                .iter()
                .filter(|subject| is_type(&subject.data));
            PassedCount {
                total: subjects.clone().count(),
                passed: subjects
                    .filter(|subject| {
                        assignments
                            .get(&subject.id)
                            .is_some_and(|assignment| assignment.passed_at.is_some())
                    })
                    .count(),
            }
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let lessons_available = summary
            .lessons
            .iter()
            .filter(|lesson| lesson.available_at.timestamp() <= now)
            .map(|lesson| lesson.subject_ids.len())
            .sum();
        let (available, upcoming): (Vec<_>, Vec<_>) = summary
            .reviews
            .iter()
            .partition(|review| review.available_at.timestamp() <= now);

        Ok(ProgressOutput {
            username: user.username,
            level,
            max_level: user.subscription.max_level_granted,
            // A reset leaves the level's earlier progressions abandoned.
            level_started_at: level_progressions
                .iter()
                .rfind(|progression| {
                    progression.data.level == level && progression.data.abandoned_at.is_none()
                })
                .and_then(|progression| progression.data.unlocked_at)
                .map(|unlocked_at| unlocked_at.to_rfc3339()),
            level_kanji: passed_count(|subject| matches!(subject, Subject::Kanji(_))),
            level_radicals: passed_count(|subject| matches!(subject, Subject::Radical(_))),
            level_subjects: level_subjects
                .iter()
                .map(|subject| {
                    let srs_stage = assignments
                        .get(&subject.id)
                        .map(|assignment| assignment.srs_stage);
                    SubjectCard::new(subject, srs_stage)
                })
                .collect(),
            srs,
            lessons_available,
            reviews_available: available
                .iter()
                .map(|review| review.subject_ids.len())
                .sum(),
            forecast: upcoming
                .iter()
                .filter(|review| !review.subject_ids.is_empty())
                .map(|review| ForecastHour {
                    at: review.available_at.to_rfc3339(),
                    reviews: review.subject_ids.len(),
                })
                .collect(),
        })
    }
}
