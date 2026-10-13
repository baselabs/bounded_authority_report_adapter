defmodule BoundedAuthorityReportAdapter.DependencyDirectionTest do
  @moduledoc """
  RA3 — the dependency-direction wall (charter §6 invariant 3; strategy §3).

  The adapter depends ONLY on the public `bounded_authority_protocol` package on the edge
  path — no private runtime dependency (the `:bounded_authority` runtime app), no transport
  lib (`:replicant` / `:capstan`), and no reference to the runtime's internal
  `BoundedAuthority.` / `BoundedAuthorityWeb.` namespaces. The adapter adds a
  transport prohibition because it is the holder/signer that
  lives outside the verifier precisely so it can sign — a transport dep here would
  collapse the invariant that transports stay protocol-free (charter §6 invariant 4).

  ## Two clauses

  The wall is two-clause, mirroring the ROADMAP RA3 acceptance ("declares
  `bounded_authority_protocol` AND no `bounded_authority` runtime / no `replicant` / no
  `capstan`"):

    * **Positive** — `mix.exs` declares + pins the protocol package; `mix.lock` resolves it
      at the pin. A dep-less `mix.exs` passes every negative regex trivially ("no forbidden
      dep" is vacuously true when there are no deps at all), so the positive clause has its
      own falsifier (design §1.2, design-adversarial C2).
    * **Negative** — no forbidden dep tuple / lock entry, and no runtime-internal namespace
      reference in compiled source.

  ## Scope (design §1.6.3 — design-adversarial C1, blocking)

  The namespace scan covers BOTH compile-bearing source surfaces: `lib/**` AND
  `test/support/**`. `mix.exs:39` compiles `test/support/` into the test env alongside
  `lib/`, and `test/support/` carries signing-path code (`test_keys.ex` calls `:crypto`;
  `test_handles.ex` implements `@behaviour BoundedAuthorityReportAdapter`). A
  `BoundedAuthority.` reference landing in `test/support/` would COMPILE and RUN while a
  `lib/`-only scan stayed green — the exact silent failure the wall exists to prevent. NEVER
  `deps/` (the protocol package is allowed its own dep tree; consumer line 81) or `docs/`
  (prose naming the wall is not a coupling).

  ## RED-capable (BA-09)

  Every banned token + the deletion of the protocol dep is mutation-proven: the proof plants
  the token / deletes the dep and asserts the wall fires. A wall that scans a malformed glob
  silently returning `[]` passes green while scanning nothing — so each glob AND the positive
  clause are mutation-proven (design §1.2, consumer line 219).
  """

  # async: false: the mutation proofs plant probe files in the real lib/ and test/support/
  # trees and a concurrent run could observe them (consumer line 32). The declaration tests
  # read stable files and are fast; serializing the whole module is simpler than splitting
  # it across two modules and matches consumer's posture.
  use ExUnit.Case, async: false

  # The ALLOWED public protocol package the adapter MUST declare (the trust root for the
  # wire profile). Consumed from its Hex release: the adapter requires the published
  # `bounded_authority_protocol` package at @protocol_requirement, and the resolved lock
  # carries the Hex tuple (not a git ref) — the wall asserts BOTH below.
  #
  # The requirement is a RANGE with a security floor (owner ruling, October 6, 2026; ADR-0023
  # amendment): a library declares the range it is compatible with, and only an application
  # locks an exact version. The floor is BAP 0.8.0, the release that carries the strict
  # Ed25519 verification fix this adapter's key refusal and self-check call; the ceiling
  # (exclusive) is the next protocol minor, which is a deliberate, reviewed move. Raising the
  # floor or the ceiling moves @protocol_requirement, @protocol_floor / @protocol_ceiling and
  # mix.exs in the same commit; when that happens is governed by
  # docs/adr/0023-pin-follows-bap-releases.md.
  @protocol_app "bounded_authority_protocol"
  @protocol_requirement "~> 0.8.0"
  @protocol_floor "0.8.0"
  @protocol_ceiling "0.9.0"

  # The LOCKED version — the guard against silent lock drift. The requirement above is a
  # range, so the lock is the exact version this repository compiles and tests against. A lock
  # move (a bare `mix deps.update`, or a deliberate adoption of a newer release inside the
  # range) is a reviewed change: the same commit raises this attribute and BOTH project locks.
  @protocol_locked_version "0.8.0"

  # The requirement is acceptable only when it is a floored range: it admits the security
  # floor, admits every later release below the ceiling (so it is not an exact pin), and
  # admits nothing at or above the ceiling or below the floor (so it neither reopens 0.7.x,
  # which lacks the strict Ed25519 rule, nor floats across a protocol minor).
  defp requirement_is_floored_range?(requirement) do
    case Version.parse_requirement(requirement) do
      {:ok, parsed} ->
        Version.match?(@protocol_floor, parsed) and
          Version.match?("0.8.1", parsed) and
          Version.match?("0.8.99", parsed) and
          not Version.match?(@protocol_ceiling, parsed) and
          not Version.match?("0.7.9", parsed) and
          not Version.match?("0.7.0", parsed)

      :error ->
        false
    end
  end

  defp requirement_admits_locked_version?(requirement, locked_version) do
    Version.match?(locked_version, Version.parse_requirement!(requirement))
  end

  defp protocol_lock_line(version) do
    "\"#{@protocol_app}\": {:hex, :#{@protocol_app}, \"#{version}\","
  end

  defp protocol_locked_at?(mix_lock, version) do
    String.contains?(mix_lock, protocol_lock_line(version))
  end

  # Forbidden dep-app atoms — form-precise regex so prose does not false-positive (design
  # §1.4). A REAL dep is the tuple `{:bounded_authority, …}` / `{:replicant, …}` /
  # `{:capstan, …}`. The `(?:["']|)` terminator catches BOTH the bare-atom form
  # (`:bounded_authority,`) AND the quoted-atom forms (`:"bounded_authority",` double-quoted
  # OR `:'bounded_authority',` single-quoted — security F1 + cross-vendor: Elixir resolves all
  # three to the SAME atom and declares the SAME dependency, so a quoted forbidden atom is the
  # same coupling; `mix format` does not canonicalize the quotes; single-quoted atoms are
  # deprecated but still valid).
  # The terminator stops `{:bounded_authority_protocol` (the ALLOWED dep — "_" is a word char
  # so `\b` finds no boundary; and the quoted form ends with `_protocol"`, past the alternation)
  # and stops `{:ash_replicant` (absent here, but the wall future-proofs against the estate
  # wedge consumer documents).
  @mix_exs_forbidden ~r/\{\s*:(?:["']|)(bounded_authority|replicant|capstan)(?:["']|\b)/
  @mix_lock_forbidden ~r/"(bounded_authority|replicant|capstan)"\s*:/

  # Forbidden runtime-internal namespaces (the authority layer's mutable internals — verified
  # first-hand against `../bounded_authority/lib/`: the runtime owns `BoundedAuthority.*` AND
  # `BoundedAuthorityWeb.*`). Three rules:
  #   - `\bBoundedAuthority(Web)?\.[A-Z]` — the dotted namespace (BoundedAuthority.Authority.*,
  #     BoundedAuthorityWeb.Foo). Does NOT match `BoundedAuthorityProtocol.` (a distinct token:
  #     "Protocol" is a `.`-less continuation, not the `(Web)?` alternation) nor
  #     `BoundedAuthorityReportAdapter` (no `.` immediately after the prefix).
  #   - `\bBoundedAuthorityWeb\b` — the dotless Web namespace (alias BoundedAuthorityWeb).
  #   - `\bBoundedAuthority\b` — the dotless RUNTIME ROOT (cross-vendor claude should-fix):
  #     `alias BoundedAuthority` / `import BoundedAuthority` couple to the runtime's namespace
  #     root and are a real one-way-contract violation. The `\b` after the prefix does NOT match
  #     `BoundedAuthorityProtocol` or `BoundedAuthorityReportAdapter` ("P"/"R" are word chars —
  #     no boundary), so the allowed surfaces stay allowed. The runtime root module itself is
  #     empty (verified — `bounded_authority/lib/bounded_authority.ex` is a bare Application
  #     module with no public defs), so `BoundedAuthority.some_fn()` is not a real coupling, but
  #     the bare alias/import IS (it gates all `BoundedAuthority.*` submodules). Verified:
  #     catches `alias BoundedAuthority` + `import BoundedAuthority`, rejects
  #     `BoundedAuthorityProtocol.V1` + `BoundedAuthorityReportAdapter`.
  @runtime_internal_regexes [
    {"BoundedAuthority./BoundedAuthorityWeb. dotted namespace",
     ~r/\bBoundedAuthority(Web)?\.[A-Z]/},
    {"BoundedAuthorityWeb (dotless web namespace)", ~r/\bBoundedAuthorityWeb\b/},
    {"BoundedAuthority (dotless runtime root)", ~r/\bBoundedAuthority\b/}
  ]

  # The scan scope — BOTH compile-bearing source surfaces (design §1.6.3). mix.exs:39
  # compiles test/support/ into the test env alongside lib/. NEVER deps/ or docs/.
  @scan_dirs ~w(lib test/support)

  # TOCTOU-safe file read (consumer lines 89-94): a concurrent mutation-proof's
  # try/after-File.rm can remove a probe file between the wildcard snapshot + the read.
  # Returns nil ONLY on :enoent (the file vanished — the TOCTOU case the design §1.8 scopes
  # this to) instead of raising File.Error (which would flake the wall). gate-integrity F1:
  # a blanket {:error, _} catch would silently skip a permission-denied offender (chmod 000)
  # — the namespace scan would pass GREEN while a real BoundedAuthority.* ref sat on disk.
  # Narrowing to :enoent means any OTHER read failure (permission denied, IO error) RAISES
  # loudly rather than laundering the verdict; the wall's RED must be trustworthy.
  defp safe_read(path) do
    case File.read(path) do
      {:ok, contents} -> contents
      {:error, :enoent} -> nil
    end
  end

  # The full scan set: the dep declarations + every compiled source file under @scan_dirs.
  defp scan_files do
    ["mix.exs", "mix.lock"] ++ source_files()
  end

  # The compiled-source glob over @scan_dirs (lib/ + test/support/). A malformed glob
  # returning [] is caught by the coverage guard (BA-09).
  defp source_files do
    Enum.flat_map(@scan_dirs, fn dir ->
      if File.dir?(dir) do
        Path.wildcard(Path.join(dir, "**/*.{ex,exs}"))
      else
        []
      end
    end)
  end

  # The namespace scan over a file list. Returns [{file, token}] offenders.
  defp namespace_offenders(files) do
    for file <- files,
        contents <- [safe_read(file)],
        contents != nil,
        {token, re} <- @runtime_internal_regexes,
        Regex.match?(re, contents),
        do: {file, token}
  end

  # ----------------------------------------------------------------- positive clause

  describe "the protocol package is declared and pinned" do
    test "mix.exs declares :#{@protocol_app}" do
      mix_exs = File.read!("mix.exs")

      assert String.contains?(mix_exs, ":#{@protocol_app}"),
             "mix.exs must declare the :#{@protocol_app} dependency (the public wire-profile " <>
               "trust root — charter §6 invariant 3; strategy §3)"
    end

    test "mix.exs requires the protocol package at @protocol_requirement" do
      mix_exs = File.read!("mix.exs")

      assert String.contains?(mix_exs, "{:#{@protocol_app}, \"#{@protocol_requirement}\"}"),
             "mix.exs must require the Hex package :#{@protocol_app} at " <>
               "#{@protocol_requirement} (the published wire-profile trust root; a version bump " <>
               "raises @protocol_requirement here in the same commit)"
    end

    test "mix.lock resolves the protocol package from Hex, not a git ref" do
      mix_lock = File.read!("mix.lock")

      assert String.contains?(mix_lock, "{:hex, :#{@protocol_app},"),
             "mix.lock must resolve :#{@protocol_app} from Hex (a `{:git, ...}` resolution " <>
               "would reintroduce the pre-publication private-dep coupling the wall forbids)"

      refute String.contains?(mix_lock, "{:git, :#{@protocol_app},"),
             "mix.lock must NOT resolve :#{@protocol_app} from a git ref"
    end

    test "mix.lock resolves the protocol package at @protocol_locked_version (no silent drift)" do
      mix_lock = File.read!("mix.lock")

      # The predicate TERMINATES at the comma after the version: an unterminated
      # prefix would match "0.2.0" inside "0.2.0-rc.1" — reopening the exact
      # silent-drift hole this clause closes.
      assert protocol_locked_at?(mix_lock, @protocol_locked_version),
             "mix.lock must resolve :#{@protocol_app} at exactly #{@protocol_locked_version} — " <>
               "a silent `mix deps.update` lock drift crossed an unreviewed protocol span. " <>
               "A version bump is deliberate: raise the mix.exs requirement + both wall " <>
               "attributes + the lock in the SAME commit"
    end

    test "@protocol_requirement is a floored range that admits the locked version" do
      assert requirement_is_floored_range?(@protocol_requirement),
             "the requirement #{@protocol_requirement} must admit the security floor " <>
               "#{@protocol_floor} and later releases below #{@protocol_ceiling}, and nothing " <>
               "older or at the ceiling (a library declares a range; only an application " <>
               "locks an exact version)"

      assert requirement_admits_locked_version?(@protocol_requirement, @protocol_locked_version),
             "the requirement #{@protocol_requirement} does not admit the locked version " <>
               "#{@protocol_locked_version}"

      assert Version.compare(@protocol_locked_version, @protocol_floor) != :lt,
             "the locked version #{@protocol_locked_version} is below the security floor " <>
               "#{@protocol_floor}"

      assert Version.compare(@protocol_locked_version, @protocol_ceiling) == :lt,
             "the locked version #{@protocol_locked_version} is at or above the ceiling " <>
               "#{@protocol_ceiling}"
    end

    test "the requirement declared in mix.exs is itself a floored range" do
      # Reads the declaration, not the attribute: a mix.exs edited to `~> 0.7` or back to an
      # exact pin reds on the predicate even if the attribute above were edited to match.
      mix_exs = File.read!("mix.exs")

      [_, declared] =
        Regex.run(~r/\{:#{@protocol_app},\s*"([^"]+)"/, mix_exs) ||
          flunk("mix.exs does not declare :#{@protocol_app} with a string requirement")

      assert requirement_is_floored_range?(declared),
             "mix.exs declares :#{@protocol_app} at #{inspect(declared)}, which is not a " <>
               "floored range (>= #{@protocol_floor}, < #{@protocol_ceiling}, not an exact pin)"

      assert requirement_admits_locked_version?(declared, @protocol_locked_version)
    end

    test "the floored-range predicate reds on a requirement that admits 0.7.x" do
      # 0.7.x lacks the strict Ed25519 rule this adapter calls: `~> 0.7` and `>= 0.7.0` admit
      # it (and `~> 0.7` also floats to 0.9.0 and beyond); `~> 0.7.0` is the 0.7 line itself.
      for requirement <- ["~> 0.7", "~> 0.7.0", ">= 0.7.0", ">= 0.7.0 and < 0.9.0"] do
        refute requirement_is_floored_range?(requirement),
               "the requirement #{requirement} admits a protocol release below the " <>
                 "#{@protocol_floor} security floor and the wall would stay green"
      end
    end

    test "the floored-range predicate reds on an exact pin" do
      # An exact pin is the retired policy: a library that pins one version blocks every
      # consumer that holds the same package at a later compatible release.
      for requirement <- ["== 0.8.0", "== 0.8.1", "0.8.0"] do
        refute requirement_is_floored_range?(requirement),
               "the exact requirement #{requirement} satisfies the wall; the ruling is a " <>
                 "range, not an exact pin"
      end
    end

    test "the floored-range predicate reds on a range that floats across the ceiling" do
      for requirement <- ["~> 0.8", ">= 0.8.0", ">= 0.8.0 and < 1.0.0"] do
        refute requirement_is_floored_range?(requirement),
               "the requirement #{requirement} admits #{@protocol_ceiling} or later; crossing " <>
                 "a protocol minor is a deliberate, reviewed move"
      end
    end

    test "the floored-range predicate reds on a floor above 0.8.0 and on an unparsable string" do
      for requirement <- ["~> 0.8.1", "~> 0.8.2", "not a requirement", ""] do
        refute requirement_is_floored_range?(requirement),
               "the requirement #{inspect(requirement)} must not satisfy the wall"
      end
    end

    test "the lock-membership predicate reds when the lock leaves the range" do
      refute requirement_admits_locked_version?(@protocol_requirement, "0.7.0")
      refute requirement_admits_locked_version?(@protocol_requirement, "0.9.0")
      assert requirement_admits_locked_version?(@protocol_requirement, "0.8.3")
    end
  end

  # ------------------------------------------------- negative clause — no forbidden dep

  describe "no forbidden dependency (the one-way contract)" do
    test "mix.exs declares no forbidden dep tuple" do
      mix_exs = File.read!("mix.exs")

      assert not Regex.match?(@mix_exs_forbidden, mix_exs),
             "a forbidden dependency tuple was found in mix.exs — the adapter must depend on " <>
               "the public protocol package ONLY, NEVER the :bounded_authority runtime app " <>
               "(charter §3) or the :replicant / :capstan transport libs (charter §6 invariant " <>
               "4; strategy §3). (Documentation prose that names the forbidden atom is fine — " <>
               "a real dep is the tuple form.)"
    end

    test "mix.lock resolves no forbidden package" do
      mix_lock = File.read!("mix.lock")

      assert not Regex.match?(@mix_lock_forbidden, mix_lock),
             "a forbidden package resolved into mix.lock — the runtime app or a transport lib " <>
               "in the lock is a dependency-direction violation. (:bounded_authority_protocol " <>
               "— the public package — is allowed; the bare :bounded_authority runtime app, " <>
               ":replicant, and :capstan are not.)"
    end
  end

  # ------------------------------------- negative clause — no runtime-internal namespace

  describe "no runtime-internal module leak into compiled source" do
    test "no file under lib/ or test/support/ references a runtime-internal module" do
      offenders = namespace_offenders(source_files())

      assert offenders == [],
             "runtime-internal reference(s) found in compiled source: #{inspect(offenders)} — " <>
               "the adapter must consume ONLY the public BoundedAuthorityProtocol. surface, " <>
               "never the BoundedAuthority.* / BoundedAuthorityWeb.* runtime internals " <>
               "(charter §3; ADR 0003)"
    end
  end

  # --------------------------------------------------- scan coverage is real (BA-09)

  describe "the scan coverage is real (a malformed glob returning [] is caught)" do
    test "scan_files/0 covers the key anchor files + every compile-bearing source scope" do
      files = scan_files()

      assert "mix.exs" in files
      assert "mix.lock" in files

      assert Enum.any?(files, &String.starts_with?(&1, "lib/")),
             "lib/ wildcard returned no files"

      assert Enum.any?(files, &String.starts_with?(&1, "test/support/")),
             "test/support/ wildcard returned no files (the C1 compile-bearing scope is silently unscanned)"
    end
  end

  # --------------------------------------------------- the wall is mutation-proven

  describe "the wall is mutation-proven (each banned token + the positive clause fires)" do
    # BA-09's lesson (consumer line 219): a wall that scans a malformed glob silently returning
    # [] passes green while scanning nothing. Each proof plants the banned token in a real
    # file / synthesizes the offending form, invokes the real scan, and asserts the wall
    # fires. Probe filenames are unique per-run so a concurrent test can't collide; on_exit /
    # after guarantees cleanup even on assertion failure; the proof refuses to overwrite a
    # pre-existing file. async: false (module-level): the proofs plant probe files in the real
    # tree.

    test "the lib/ glob catches a planted runtime-internal token" do
      unique = System.unique_integer([:positive])
      pid = :erlang.pid_to_list(self()) |> Enum.join("")
      probe = "lib/_ra3_dep_probe_#{unique}_#{pid}.exs"

      refute File.exists?(probe),
             "a pre-existing file at #{probe} blocks the mutation proof " <>
               "(rename or remove it); the proof will not overwrite real content"

      try do
        File.write!(probe, "# probe alias BoundedAuthority.Authority.DecisionOps\n")

        # correctness F1: scan via the PRODUCTION source_files/0 (filtered to the lib/ scope),
        # NOT a separately-constructed glob — a proof that builds its own glob tests a
        # different path than the wall runs in production. source_files/0 is the production
        # scan; filtering it by prefix proves the lib/ scope of THAT scan is non-vacuous.
        offenders =
          source_files()
          |> Enum.filter(&String.starts_with?(&1, "lib/"))
          |> namespace_offenders()

        assert offenders != [],
               "the lib/ mutation proof failed — a planted runtime-internal token was NOT caught " <>
                 "(a malformed glob returning [] would cause this; the lib/ scope is silently unscanned)"
      after
        # File.rm!/1 raises on deletion failure (cross-vendor codex should-fix: a swallowed
        # File.rm/1 would leave the probe — a real BoundedAuthority.* ref — in compiled source).
        File.rm!(probe)
      end
    end

    test "the test/support/ glob catches a planted runtime-internal token (the C1 scope)" do
      # design-adversarial C1: test/support/ is compiled (mix.exs:39) and carries signing-path
      # code. A BoundedAuthority.* ref landing here COMPILES and RUNS while a lib/-only scan
      # stayed green. This proof pins that the test/support/ scope is scanned.
      unique = System.unique_integer([:positive])
      pid = :erlang.pid_to_list(self()) |> Enum.join("")
      probe = "test/support/bounded_authority_report_adapter/_ra3_dep_probe_#{unique}_#{pid}.exs"

      refute File.exists?(probe),
             "a pre-existing file at #{probe} blocks the mutation proof"

      try do
        File.write!(probe, "# probe alias BoundedAuthority.Authority.ConsumptionOps\n")

        # correctness F1: scan via the PRODUCTION source_files/0 (filtered to test/support/),
        # NOT a separately-constructed glob.
        offenders =
          source_files()
          |> Enum.filter(&String.starts_with?(&1, "test/support/"))
          |> namespace_offenders()

        assert offenders != [],
               "the test/support/ mutation proof failed — a planted runtime-internal token was " <>
                 "NOT caught (the test/support/ compile-bearing scope is silently unscanned; a " <>
                 "BoundedAuthority.* ref here would compile + run green while the wall passed)"
      after
        File.rm!(probe)
      end
    end

    test "the real adapter module path is scanned (a planted token in the real .ex fires)" do
      # consumer's Task-8 pattern (lines 296-326): mutate the REAL lib/bounded_authority_report_adapter.ex
      # — the module the wall exists to guard. A glob that silently skipped the real module
      # (a malformed recursion, a path case the probe files did not exercise) would let a
      # BoundedAuthority.* ref land in the adapter and pass the wall. Mutating the real file
      # (not a copy) + cleaning up in try/after is the only proof that the actual path is in
      # the scan's result set.
      adapter_path = "lib/bounded_authority_report_adapter.ex"
      original = File.read!(adapter_path)

      try do
        File.write!(adapter_path, original <> "\n# probe alias BoundedAuthority.Authority\n")

        # correctness F1: scan via the PRODUCTION source_files/0 (filtered to lib/), so the
        # proof exercises the production glob path.
        offenders =
          source_files()
          |> Enum.filter(&String.starts_with?(&1, "lib/"))
          |> namespace_offenders()

        assert Enum.any?(offenders, fn {file, _token} -> file == adapter_path end),
               "the real-module mutation proof failed — a planted BoundedAuthority.Authority ref " <>
                 "in the real adapter module was NOT caught (the module the wall guards is " <>
                 "silently unscanned): #{inspect(offenders)}"
      after
        # Restore the EXACT original bytes. The mutation proof MUST clean up after itself —
        # a concurrent run (or a follow-on test) must never observe the probe, and the wall's
        # own GREEN assertion must see the un-mutated file.
        File.write!(adapter_path, original)
      end
    end

    test "the dotless runtime-root alias is caught (cross-vendor: alias/import BoundedAuthority)" do
      # cross-vendor claude should-fix: `alias BoundedAuthority` / `import BoundedAuthority`
      # couple to the runtime's namespace root (gating all BoundedAuthority.* submodules) but
      # were missed by the dotted regex (no `.[A-Z]` after the prefix). The dotless
      # `\bBoundedAuthority\b` guard closes the gap; this proof pins that it fires.
      root_refs = [
        "alias BoundedAuthority",
        "import BoundedAuthority",
        "alias BoundedAuthority, as: BA"
      ]

      for ref <- root_refs do
        offenders =
          for {token, re} <- @runtime_internal_regexes,
              Regex.match?(re, ref),
              do: token

        assert offenders != [],
               "the bare runtime-root reference #{inspect(ref)} was NOT caught — alias/import " <>
                 "BoundedAuthority couple to the runtime namespace and must trip the wall " <>
                 "(cross-vendor claude should-fix): #{inspect(offenders)}"
      end
    end

    test "the positive clause reds when the protocol dep is removed (a dep-less mix.exs is caught)" do
      # design-adversarial C2: a dep-less mix.exs passes every negative regex trivially ("no
      # forbidden dep" is vacuously true when there are no deps at all). The positive clause is the
      # falsifier — remove the protocol dep from an in-memory copy and assert the declaration
      # assertion reds.
      mix_exs = File.read!("mix.exs")

      depless =
        String.replace(
          mix_exs,
          ~r/\{\s*:#{@protocol_app},[^}]*\},?/,
          ""
        )

      refute String.contains?(depless, ":#{@protocol_app}"),
             "the dep-removal fixture did not strip the protocol dep — the positive-clause " <>
               "mutation proof is not exercising the red path (the fixture itself is broken)"
    end

    test "the lock-version clause reds on a drifted lock (plain bump + prefix extension)" do
      # Two mutations, one per real hole. A plain drift (0.2.1 — a stale or manually
      # altered lock; a bare `mix deps.update` reconciles the lock inside the range, which this clause catches) exercises
      # the obvious red. The PREFIX EXTENSION (0.2.0-rc.1) exercises the one an
      # unterminated predicate would still match: mutating to 0.2.1
      # alone passes even while the prefix hole is open, so the proof would mask the very
      # defect the terminator in the clause above exists to prevent. Fixture discipline
      # follows the
      # C2 shape above: in-memory String.replace, refute the production predicate on the
      # mutated copy.
      locked_line = protocol_lock_line(@protocol_locked_version)

      real_lock = File.read!("mix.lock")

      assert protocol_locked_at?(real_lock, @protocol_locked_version),
             "fixture setup: the real lock does not carry the locked-version line — the " <>
               "green clause above is red and must be fixed before this proof means anything"

      for drifted <- ["0.2.1", "0.2.0-rc.1"] do
        drifted_line = "\"#{@protocol_app}\": {:hex, :#{@protocol_app}, \"#{drifted}\","
        mutated_lock = String.replace(real_lock, locked_line, drifted_line)

        refute mutated_lock == real_lock,
               "the drift fixture for #{drifted} did not change the lock — the mutation " <>
                 "proof is not exercising the red path (the fixture itself is broken)"

        refute protocol_locked_at?(mutated_lock, @protocol_locked_version),
               "a lock drifted to #{drifted} still satisfies the locked-version clause — " <>
                 "the wall would stay green across an unreviewed protocol span"
      end
    end

    test "the protocol namespace is ALLOWED (BoundedAuthorityProtocol. never trips the wall)" do
      # Belt-and-suspenders: the public protocol package IS the allowed surface. A
      # BoundedAuthorityProtocol.* reference must NOT match any runtime-internal regex
      # (false-positive here would forbid the legit public surface).
      protocol_refs = [
        "alias BoundedAuthorityProtocol.V1",
        "BoundedAuthorityProtocol.V1.check_envelope/2",
        "{:ok, %BoundedAuthorityProtocol.V1.EnvelopeFacts{}}"
      ]

      for ref <- protocol_refs do
        offenders =
          for {token, re} <- @runtime_internal_regexes,
              Regex.match?(re, ref),
              do: token

        assert offenders == [],
               "the protocol reference #{inspect(ref)} tripped a runtime-internal regex " <>
                 "(false-positive — the public protocol surface must stay allowed): #{inspect(offenders)}"
      end
    end

    test "the adapter's own namespace is ALLOWED (BoundedAuthorityReportAdapter never trips the wall)" do
      # The adapter's own module name must not trip its own wall. BoundedAuthorityReportAdapter
      # has no `.` immediately after the BoundedAuthority prefix, so the namespace regex does
      # not match (design §1.6 / Q4).
      own_refs = [
        "defmodule BoundedAuthorityReportAdapter do",
        "alias BoundedAuthorityReportAdapter.Keys.RawKey",
        "@behaviour BoundedAuthorityReportAdapter"
      ]

      for ref <- own_refs do
        offenders =
          for {token, re} <- @runtime_internal_regexes,
              Regex.match?(re, ref),
              do: token

        assert offenders == [],
               "the adapter's own reference #{inspect(ref)} tripped a runtime-internal regex " <>
                 "(false-positive — the adapter's own namespace must stay allowed): #{inspect(offenders)}"
      end
    end

    test "the mix.exs dep-tuple form is caught for each forbidden atom, not the protocol" do
      # Form-precise: a REAL dep is the tuple form. The wall fires on that form, not on
      # documentation prose or the allowed protocol tuple.
      assert Regex.match?(@mix_exs_forbidden, "{:bounded_authority, \"~> 1.0\"}")
      assert Regex.match?(@mix_exs_forbidden, "{:replicant, \"~> 1.0\"}")
      assert Regex.match?(@mix_exs_forbidden, "{:capstan, \"~> 1.0\"}")
      assert Regex.match?(@mix_exs_forbidden, "{:bounded_authority,\n git: \"...\"}")

      # security F1: Elixir resolves :"bounded_authority" to the SAME atom as
      # :bounded_authority and declares the SAME dependency — so the quoted-atom form is the
      # same coupling and must be caught. (mix format does not canonicalize the quotes.)
      # cross-vendor: single-quoted atoms :'bounded_authority' are deprecated but still valid
      # and parse to the same atom — both quote forms are caught.
      assert Regex.match?(@mix_exs_forbidden, "{:\"bounded_authority\", \"~> 1.0\"}")
      assert Regex.match?(@mix_exs_forbidden, "{:\"replicant\", \"~> 1.0\"}")
      assert Regex.match?(@mix_exs_forbidden, "{:\"capstan\", \"~> 1.0\"}")
      assert Regex.match?(@mix_exs_forbidden, "{:'bounded_authority', \"~> 1.0\"}")
      assert Regex.match?(@mix_exs_forbidden, "{:'replicant', \"~> 1.0\"}")
      assert Regex.match?(@mix_exs_forbidden, "{:'capstan', \"~> 1.0\"}")

      # The protocol tuple (the allowed form) does NOT match — bare OR double/single-quoted.
      refute Regex.match?(@mix_exs_forbidden, "{:bounded_authority_protocol, ...}")
      refute Regex.match?(@mix_exs_forbidden, "{:\"bounded_authority_protocol\", ...}")
      refute Regex.match?(@mix_exs_forbidden, "{:'bounded_authority_protocol', ...}")
      # Prose mentioning a forbidden atom does NOT match (it's documentation).
      refute Regex.match?(@mix_exs_forbidden, "# never the :bounded_authority app")
      refute Regex.match?(@mix_exs_forbidden, "# no :replicant / :capstan transport lib")
      # ash_replicant (absent here, but the estate wedge) does NOT match — bare OR quoted.
      refute Regex.match?(@mix_exs_forbidden, "{:ash_replicant, \"~> 1.0\"}")
      refute Regex.match?(@mix_exs_forbidden, "{:\"ash_replicant\", \"~> 1.0\"}")
      refute Regex.match?(@mix_exs_forbidden, "{:'ash_replicant', \"~> 1.0\"}")
    end

    test "the mix.lock entry form is caught for each forbidden atom, not the protocol" do
      # design-adversarial C5: consumer's reference (lines 362-369) synthesizes the offending
      # lock-entry form AND the allowed form at the STRING level. The three-atom alternation
      # is a generalization beyond consumer's single-atom lock regex, so each atom gets a
      # synthesized-string proof.
      assert Regex.match?(@mix_lock_forbidden, ~s("bounded_authority": {:git, ...}))
      assert Regex.match?(@mix_lock_forbidden, ~s("replicant": {:hex, ...}))
      assert Regex.match?(@mix_lock_forbidden, ~s("capstan": {:hex, ...}))

      refute Regex.match?(
               @mix_lock_forbidden,
               ~s("bounded_authority_protocol": {:git, ...})
             )
    end
  end
end
