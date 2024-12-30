# Limitations

`zizmor` can help you write more secure GitHub workflow and action definitions,
as well as help you find exploitable bugs in existing definitions.

However, like all tools, `zizmor` is **not a panacea**, and has
fundamental limitations that must be kept in mind. This page
documents some of those limitations.

## `zizmor` is a _static_ analysis tool

`zizmor` is a _static_ analysis tool. It never executes any code, nor does it
have access to any runtime state.

In contrast, GitHub Actions workflow and action definitions are highly
dynamic, and can be influenced by inputs that can only be inspected at
runtime.

For example, here is a workflow where a job's matrix is generated
at runtime by a previous job, making the matrix impossible to
analyze statically:

```yaml
build-matrix:
  name: Build the matrix
  runs-on: ubuntu-latest
  outputs:
    matrix: ${{ steps.set-matrix.outputs.matrix }}
  steps:
    - id: set-matrix
      run: |
        echo "matrix=$(python generate_matrix.py)" >> "${GITHUB_OUTPUT}"

run:
  name: ${{ matrix.name }}
  needs:
    - build-matrix
  runs-on: ubuntu-latest
  strategy:
    matrix: ${{ fromJson(needs.build-matrix.outputs.matrix) }}
  steps:
    - run: |
        echo "hello ${{ matrix.something }}"
```

In the above, the expansion of `${{ matrix.something }}` is entirely controlled
by the output of `generate_matrix.py`, which is only known at runtime.

In such cases, `zizmor` will err on the side of verbosity. For example,
the [template-injection](./audits.md#template-injection) audit will flag
`${{ matrix.something }}` as a potential code injection risk, since it
can't infer anything about what `matrix.something` might expand to.

## `zizmor` audits workflow and action _definitions_ only

`zizmor` audits workflow and action _definitions_ only. That means the
contents of `foo.yml` (for your workflow definitions) or `action.yml` (for your
composite action definitions).

In practice, this means that `zizmor` does **not** analyze other files
referenced by workflow and action definitions. For example:

```yaml
example:
  runs-on: ubuntu-latest
  steps:
    - name: step-1
      run: |
        echo foo=$(bar) >> $GITHUB_ENV

    - name: step-2
      run: |
        # some-script.sh contains the same code as step-1
        ./some-script.sh
```

`zizmor` can analyze `step-1` above, because the code it executes
is present within the workflow definition itself. It *cannot* analyze
`step-2` beyond the presence of a script execution, since it doesn't
audit shell scripts or any other kind of files.

More generally, `zizmor` cannot analyze files indirectly referenced within
workflow/action definitions, as they may not actually exist until runtime.
For example, `some-script.sh` above may have been generated or downloaded
outside of any repository-tracked state.
