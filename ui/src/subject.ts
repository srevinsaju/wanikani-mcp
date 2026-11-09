// The ui://wanikani/subject bundle: connects to the host and draws the view.

import { connect } from "./host";
import type { GetSubjectsOutput } from "./output";
import { render } from "./views/subject";

void connect<GetSubjectsOutput>("wanikani-subject", render);
