// The ui://wanikani/progress bundle: connects to the host and draws the view.

import { connect } from "./host";
import type { ProgressOutput } from "./output";
import { render } from "./views/progress";

void connect<ProgressOutput>("wanikani-progress", render);
