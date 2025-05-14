# e2e-menagerie

This directory behaves like a pseudo GitHub repository. It contains a
`.github/workflows` directory with some sample workflows, as well as a
handful of custom action definitions. It also contains a `.gitignore`
to ensure that we handle ignored files correctly.

The actual contents of these workflows and actions are not important;
what's important is that they remain static so that `zizmor`'s
snapshot tests don't change.
