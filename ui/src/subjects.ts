// The ui://wanikani/subjects bundle: connects to the host and draws the view.

import { connect } from "./host";
import type { SubjectsOutput } from "./output";
import { render } from "./views/subjects";

void connect<SubjectsOutput>("wanikani-subjects", render);
