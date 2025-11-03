name: "contracts-validate"

permissions:
  contents: read

concurrency:
  # Keep PR-specific groups to prevent cross-branch cancellations.
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true

on:
  workflow_dispatch: {}
  push:
    paths:
      - "json/**"
      - "proto/**"
      - "fixtures/**"
      - ".github/workflows/**"   # ensure pin guard runs when ANY workflow changes
  pull_request:
    paths:
      - "json/**"
      - "proto/**"
      - "fixtures/**"
      - ".github/workflows/**"   # ensure pin guard runs when ANY workflow changes

defaults:
  run:
    shell: bash --noprofile --norc -euo pipefail {0}

env:
  FAIL_ON_NO_BASE: "1"
  ALLOW_REMOVALS: "0"

jobs:
  version-sync-check:
    name: "Security: enforce static pin for contracts reusable workflow"
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 1
          persist-credentials: false

      - name: Verify 'uses:' pins for heimgewebe/contracts
        env:
          REQUIRED_REPO: "heimgewebe/contracts/.github/workflows/contracts-ajv-reusable.yml"
          REQUIRED_REF: "contracts-v1"
        run: |
          set -euo pipefail
          shopt -s extglob

          files=()
          while IFS= read -r -d '' f; do files+=("$f"); done < \
            <(git ls-files -z -- '.github/workflows/*.yml' '.github/workflows/*.yaml' || true)

          [[ ${#files[@]} -gt 0 ]] || { echo "::notice::No workflow files"; exit 0; }

          extract_pair() {
            local line="$1"
            line="${line%%#*}"
            line="${line##+([[:space:]])}"
            line="${line%%+([[:space:]])}"
            if [[ "$line" =~ ^(-[[:space:]]*)?uses:[[:space:]]*'([^']+)' ]]; then
              echo "${BASHREMATCH[2]}"; return 0
            fi
            if [[ "$line" =~ ^(-[[:space:]]*)?uses:[[:space:]]*\"([^\"]+)\" ]]; then
              echo "${BASHREMATCH[2]}"; return 0
            fi
            if [[ "$line" =~ ^(-[[:space:]]*)?uses:[[:space:]]*([^[:space:]#]+) ]]; then
              echo "${BASHREMATCH[2]}"; return 0
            fi
            return 1
          }

          check_pair() {
            local wf="$1" repo="$2" ref="$3"
            [[ "$repo" == "$REQUIRED_REPO" ]] || return 0
            if [[ "$ref" =~ (\$\{|\$\(|\$[A-Za-z_]) ]]; then
              echo "::error file=$wf::Dynamic ref not allowed: $ref"; return 1
            fi
            if [[ "$ref" != "$REQUIRED_REF" ]]; then
              echo "::error file=$wf::Pin mismatch: expected '$REQUIRED_REF', got '$ref'"; return 1
            fi
            return 0
          }

          mismatches=0
          for wf in "${files[@]}"; do
            while IFS= read -r line || [[ -n "$line" ]]; do
              if pair="$(extract_pair "$line")"; then
                [[ "$pair" == *"@"* ]] || continue
                repo="${pair%@*}"; ref="${pair#*@}"
                if ! check_pair "$wf" "$repo" "$ref"; then mismatches=1; fi
              fi
            done < "$wf"
          done

          [[ $mismatches -eq 0 ]] || exit 1
          echo "::notice::✅ All version pins validated"

  guard:
    name: "Security: guard deletion policy (json/proto)"
    runs-on: ubuntu-latest
    timeout-minutes: 8
    env:
      GH_DEFAULT_BRANCH: ${{ github.event.repository.default_branch || 'main' }}
      GH_PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}
      GH_PUSH_BEFORE: ${{ github.event.before }}
      PROTECTED_REGEX: '^(json|proto)/'
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false

      - name: Enforce guard policy
        run: |
          set -euo pipefail
          is_truthy() { case "${1:-0}" in 1|true|yes|on) return 0 ;; esac; return 1; }

          if is_truthy "${ALLOW_REMOVALS:-0}"; then
            echo "::notice::ALLOW_REMOVALS=1 → skipping guard"
            exit 0
          fi

          base=""
          base_src=""

          if [[ -n "${GH_PR_BASE_SHA:-}" ]] && git rev-parse --verify "${GH_PR_BASE_SHA}^{commit}" &>/dev/null; then
            if mb="$(git merge-base "$GH_PR_BASE_SHA" HEAD 2>/dev/null)"; then
              base="$mb"; base_src="merge-base(pr_base,HEAD)"
            fi
          fi

          if [[ -z "$base" && -n "${GH_PUSH_BEFORE:-}" && ! "${GH_PUSH_BEFORE}" =~ ^0{40}$ ]] \
             && git rev-parse --verify "${GH_PUSH_BEFORE}^{commit}" &>/dev/null; then
            base="$GH_PUSH_BEFORE"; base_src="push_before"
          fi

          if [[ -z "$base" ]]; then
            git fetch -q origin "${GH_DEFAULT_BRANCH}" || true
            if git rev-parse "origin/${GH_DEFAULT_BRANCH}^{commit}" &>/dev/null; then
              if mb="$(git merge-base "origin/${GH_DEFAULT_BRANCH}" HEAD 2>/dev/null)"; then
                base="$mb"; base_src="merge-base(origin/${GH_DEFAULT_BRANCH},HEAD)"
              fi
            fi
          fi

          if [[ -z "$base" ]]; then
            if is_truthy "${FAIL_ON_NO_BASE:-1}"; then
              echo "::error::Cannot determine merge-base"; exit 1
            else
              echo "::notice::No merge-base found - skipping guard"; exit 0
            fi
          fi

          echo "::notice::Checking diff from ${base:0:8}...HEAD (source=$base_src)"

          blocked=()
          while IFS=$'\t' read -r -a fields; do
            status="${fields[0]}"
            p1="${fields[1]}"
            p2="${fields[2]:-}"
            [[ "$p1" =~ ${PROTECTED_REGEX} ]] || continue
            case "$status" in
              D)  blocked+=("DELETE: $p1") ;;
              R*) blocked+=("RENAME: $p1 → ${p2:-(unknown destination)}") ;;
            esac
          done < <(git diff --name-status --diff-filter=DR "${base}...HEAD")

          if (( ${#blocked[@]} )); then
            echo "::group::❌ Protected file deletions blocked"
            printf '  • %s\n' "${blocked[@]}" | sort -u
            echo "::endgroup::"
            echo "::error::Guard violation"
            exit 1
          fi

          echo "::notice::✅ Guard passed"

  validate:
    name: "Validate fixtures via reusable workflow"
    needs: [version-sync-check, guard]
    uses: heimgewebe/contracts/.github/workflows/contracts-ajv-reusable.yml@contracts-v1
    secrets: inherit
    with:
      fixtures_glob: ${{ vars.FIXTURES_GLOB || 'fixtures/**/*.jsonl' }}
