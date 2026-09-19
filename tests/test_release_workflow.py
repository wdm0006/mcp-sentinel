"""Offline tests for the release workflow's tag selection.

The Release workflow runs on two event shapes: a ``v*`` tag push, where the tag
is the ref, and a manual dispatch from a branch, where the tag is an input.
Picking one effective tag is the only logic in the workflow that can be wrong
independently of GitHub, so it lives in a shell script these tests run directly.
The rest is a structural check that the workflow consumes that tag everywhere a
release tag is needed, and that it still publishes nothing but a draft.
"""

import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
SELECT_SCRIPT = REPO_ROOT / ".github" / "scripts" / "select-release-tag.sh"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"
SELECTED_TAG = "${{ steps.release.outputs.tag }}"


def select_tag(event_name: str, dispatch_tag: str, ref_name: str):
    """Run the selection script exactly as the workflow step does."""
    return subprocess.run(
        ["bash", str(SELECT_SCRIPT), event_name, dispatch_tag, ref_name],
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    ("event_name", "dispatch_tag", "ref_name", "expected"),
    [
        ("push", "", "v0.1.0", "v0.1.0"),
        ("push", "", "v1.2.3rc1", "v1.2.3rc1"),
        ("workflow_dispatch", "v0.1.0", "main", "v0.1.0"),
        # A dispatch input wins even when the run starts on another tag.
        ("workflow_dispatch", "v0.2.0", "v0.1.0", "v0.2.0"),
    ],
)
def test_each_event_shape_selects_one_release_tag(event_name, dispatch_tag, ref_name, expected):
    result = select_tag(event_name, dispatch_tag, ref_name)

    assert result.returncode == 0, result.stderr
    assert result.stdout == f"{expected}\n"


@pytest.mark.parametrize(
    ("event_name", "dispatch_tag", "ref_name", "message"),
    [
        # The bug this replaces: a manual dispatch used the branch as the tag.
        ("workflow_dispatch", "", "main", "requires the tag input"),
        ("push", "", "main", "is not a version tag"),
        ("workflow_dispatch", "0.1.0", "main", "is not a version tag"),
        ("workflow_dispatch", "v", "main", "is not a version tag"),
        ("schedule", "", "main", "unsupported event"),
    ],
)
def test_a_tag_that_is_not_a_version_tag_fails_before_anything_is_built(
    event_name, dispatch_tag, ref_name, message
):
    result = select_tag(event_name, dispatch_tag, ref_name)

    assert result.returncode == 1
    assert message in result.stderr
    assert result.stdout == ""


def _workflow() -> dict:
    document = yaml.safe_load(WORKFLOW.read_text())
    # PyYAML reads the bare key `on:` as the boolean True.
    document["on"] = document.pop(True, document.get("on"))
    return document


def _steps() -> list[dict]:
    return _workflow()["jobs"]["build"]["steps"]


def _index_of(name: str) -> int:
    for index, step in enumerate(_steps()):
        if step.get("name") == name:
            return index
    raise AssertionError(f"release.yml has no step named {name!r}")


def test_manual_dispatch_requires_a_tag_input():
    dispatch = _workflow()["on"]["workflow_dispatch"]

    assert dispatch["inputs"]["tag"]["required"] is True


def test_the_workflow_runs_the_selection_script_this_suite_tests():
    select = _steps()[_index_of("Select the release tag")]

    assert str(SELECT_SCRIPT.relative_to(REPO_ROOT)) in select["run"]
    assert select["id"] == "release"


def test_the_selected_tag_is_checked_out_and_used_for_version_and_release():
    steps = _steps()

    assert steps[_index_of("Check out the release tag")]["with"]["ref"] == SELECTED_TAG
    assert steps[_index_of("Verify the tag matches the package version")]["env"]["RELEASE_TAG"] == (
        SELECTED_TAG
    )
    assert steps[_index_of("Attach artifacts to a draft GitHub release")]["env"]["RELEASE_TAG"] == (
        SELECTED_TAG
    )


def test_only_the_selection_step_reads_the_triggering_ref():
    # Every later step must work off the selected tag: on a manual dispatch
    # GITHUB_REF_NAME is the branch, which is what made the path unusable.
    reading_the_ref = [
        step.get("name") for step in _steps() if "GITHUB_REF_NAME" in str(step.get("run", ""))
    ]

    assert reading_the_ref == ["Select the release tag"]


def test_a_mismatched_tag_fails_before_artifacts_or_a_release_exist():
    verify = _index_of("Verify the tag matches the package version")

    assert verify < _index_of("Build sdist and wheel")
    assert verify < _index_of("Attach artifacts to a draft GitHub release")


def test_the_release_stays_a_draft_and_nothing_is_published():
    # Checked against what the steps actually run, not the file text: the header
    # comment names `uv publish` while explaining that this workflow never runs it.
    executed = "\n".join(str(step.get("run", "")) + str(step.get("uses", "")) for step in _steps())
    release = _steps()[_index_of("Attach artifacts to a draft GitHub release")]["run"]

    assert "--draft" in release
    for publisher in ("uv publish", "twine", "gh-action-pypi-publish", "PYPI_"):
        assert publisher not in executed
