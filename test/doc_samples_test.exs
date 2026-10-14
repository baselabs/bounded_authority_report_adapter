defmodule BoundedAuthorityReportAdapter.DocSamplesTest do
  @moduledoc """
  Runs the Elixir code samples in the guides and the API reference, so a sample a reader
  copies is a sample that ran.

  Every fenced `elixir` block in the guides listed in `@guides` is evaluated, in file order,
  with one shared binding per file, the way a reader pastes them into one `iex -S mix`
  session. A block may be marked with the line `<!-- doc-sample: fragment -->` directly
  above it; a fragment (an excerpt whose variables come from the reader's application) is
  parsed, not evaluated, and the guide must say in prose that it is a fragment. When the last
  line of a block is `#=> value`, the block's value, formatted with `inspect/1`, must equal
  it.

  The fenced `elixir` blocks in the API docs of `BoundedAuthorityReportAdapter` and
  `BoundedAuthorityReportAdapter.V3` continue the README quick start: each is evaluated
  with the README's final binding (plus, for `V3`, the bindings of its moduledoc's blocks).

  Evaluation diagnostics are collected, not printed. A warning fails the test unless it
  names a module the sample leaves to the reader (`MyApp.*`, or Plug, which this package
  does not depend on, including the `@impl` notes its absence causes) or is the expected
  redefinition of the development key handle that the
  README and the getting-started guide both define.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias BoundedAuthorityProtocol.V1.Json

  @root Path.expand("../", __DIR__)

  # Evaluated in this order; the API examples continue README.md's binding.
  @guides [
    "README.md",
    "docs/getting-started.md",
    "docs/consumer-integration.md",
    "docs/recipes.md",
    "docs/telemetry.md"
  ]

  # Every other public Markdown surface: it may carry only fragments.
  @fragment_only [
    "usage-rules.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "docs/errors.md",
    "docs/security.md",
    "docs/upgrading.md",
    "examples/README.md",
    "examples/edge_agent/README.md"
  ]

  @fragment_marker "<!-- doc-sample: fragment -->"
  @allowed_warning ~r/MyApp\.|Plug|redefining module MyApp\.DevKey|"@impl true" for function (init\/1|call\/2)/

  for path <- @guides ++ @fragment_only, do: @external_resource(Path.join(@root, path))

  setup_all do
    {guide_results, readme_state} =
      Enum.map_reduce(@guides, nil, fn path, readme_state ->
        result = evaluate_blocks(path, blocks_of(path), new_state())
        {{path, result}, readme_state || result.state}
      end)

    # The telemetry guide attaches a logging handler; detach it before anything else signs.
    :telemetry.detach("my-app-sign-telemetry")

    api_results = merge(evaluate_api_examples(readme_state))

    %{guides: Map.new(guide_results), api: api_results, readme_state: readme_state}
  end

  test "every runnable guide block evaluates and matches its #=> value", %{guides: guides} do
    for path <- @guides do
      result = Map.fetch!(guides, path)
      assert result.evaluated > 0, "#{path} has no evaluated block; the scan is broken"
      assert_clean(result)
    end
  end

  test "every API doc example evaluates and matches its #=> value", %{api: api} do
    # sign_* functions of both surfaces, plus the V3 moduledoc's handle.
    assert api.evaluated >= 11, "only #{api.evaluated} API examples ran; the scan is broken"
    assert_clean(api)
  end

  test "every public signing function documents an evaluated example" do
    for module <- [BoundedAuthorityReportAdapter, BoundedAuthorityReportAdapter.V3],
        {{:function, name, 3}, _anno, _sig, %{"en" => doc}, _meta} <- function_docs(module),
        String.starts_with?(Atom.to_string(name), "sign_") do
      assert code_blocks(doc) != [],
             "#{inspect(module)}.#{name}/3 has no fenced elixir example in its @doc"
    end
  end

  test "fragment-only guides carry no unmarked elixir block, and every fragment parses" do
    for path <- @guides ++ @fragment_only, block <- blocks_of(path) do
      location = "#{path}:#{block.line}"

      if path in @fragment_only do
        assert block.fragment?, "#{location} is an unmarked elixir block in a fragment-only doc"
      end

      if block.fragment? do
        assert {:ok, _quoted} = Code.string_to_quoted(block.code), "#{location} does not parse"
      end
    end
  end

  test "no public doc hides Elixir under another fence language" do
    for path <- @guides ++ @fragment_only do
      text = File.read!(Path.join(@root, path))

      refute Regex.match?(~r/^```(ex|exs|iex|elixir-)\b/m, text),
             "#{path} uses a fence language this test does not run"
    end
  end

  test "the README and getting-started define the same development key handle" do
    [readme_handle, guide_handle] =
      for path <- ["README.md", "docs/getting-started.md"] do
        path |> blocks_of() |> Enum.find(&(&1.code =~ "defmodule MyApp.DevKey")) |> Map.get(:code)
      end

    assert readme_handle == guide_handle
  end

  test "the consumer-integration verifier accepts a real envelope and rejects the rest",
       %{readme_state: %{binding: binding}} do
    holder = Keyword.fetch!(binding, :holder)
    grant = Keyword.fetch!(binding, :grant)
    now = Keyword.fetch!(binding, :now)
    # The guides define these modules at run time, so they are looked up by name.
    dev_key = doc_module("DevKey")
    verifier = doc_module("EnvelopeVerifier")
    {:ok, issuer_public_key} = dev_key.public_key({:issuer, "issuer-key-1"})
    {:ok, holder_public_key} = dev_key.public_key({:holder, "holder-key-1"})
    {:ok, stranger_public_key} = dev_key.public_key({:holder, "stranger-key-1"})

    raw_body = ~s({"document":"minutes-2026-10-01.pdf"})
    {:ok, cast_arguments} = Json.decode(raw_body)
    invocation_id = "0c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f"

    {:ok, %{proof: proof}} =
      BoundedAuthorityReportAdapter.sign_report(
        %{
          grant_compact: grant,
          operation: "archive_document",
          method: "POST",
          target_uri: "https://records.example/archive",
          invocation_id: invocation_id,
          cast_arguments: cast_arguments,
          nonce: "nonce-consumer-1"
        },
        holder,
        %{issued_at: now}
      )

    headers = %{
      "x-ba-grant" => grant,
      "x-ba-proof" => proof,
      "x-ba-invocation-id" => invocation_id,
      "x-ba-nonce" => "nonce-consumer-1"
    }

    config = %{
      issuer_key_id: "issuer-key-1",
      issuer_public_key: issuer_public_key,
      issuer: "https://issuer.example",
      audience: "https://records.example",
      target_uri: "https://records.example/archive",
      operation: "archive_document",
      clock_skew: 60,
      proof_max_age: 300
    }

    assert {:ok, %{operation: "archive_document"}} =
             verifier.verify(raw_body, headers, holder_public_key, config)

    assert verifier.verify(raw_body, headers, stranger_public_key, config) == :invalid
    other_body = ~s({"document":"minutes-2026-10-02.pdf"})
    assert verifier.verify(other_body, headers, holder_public_key, config) == :invalid

    assert verifier.verify(raw_body, Map.delete(headers, "x-ba-nonce"), holder_public_key, config) ==
             :invalid
  end

  test "the telemetry guide's handler logs a signing call and stays attached" do
    doc_module("SignTelemetry").attach()

    try do
      log =
        capture_log([level: :info], fn ->
          BoundedAuthorityReportAdapter.sign_report(%{}, {doc_module("DevKey"), {:holder, "h"}})
        end)

      assert log =~ "signed report: invalid_input in "

      assert Enum.any?(
               :telemetry.list_handlers([:bounded_authority_report_adapter, :sign, :stop]),
               &(&1.id == "my-app-sign-telemetry")
             )
    after
      :telemetry.detach("my-app-sign-telemetry")
    end
  end

  defp doc_module(name), do: Module.concat(["MyApp", name])

  ## evaluation

  defp new_state do
    %{binding: [], env: Code.env_for_eval([])}
  end

  # Evaluates the non-fragment blocks of one source in order, threading binding and env.
  defp evaluate_blocks(source, blocks, state) do
    Enum.reduce(blocks, %{state: state, evaluated: 0, failures: [], warnings: []}, fn
      %{fragment?: true}, acc ->
        acc

      block, acc ->
        location = "#{source}:#{block.line}"
        {outcome, diagnostics} = run_block(block, acc.state, location)

        warnings =
          for %{severity: :warning, message: message} <- diagnostics,
              not Regex.match?(@allowed_warning, message),
              do: "#{location}: #{message}"

        case outcome do
          {:ok, value, state} ->
            failures = check_expected(block, value, location)

            %{
              acc
              | state: state,
                evaluated: acc.evaluated + 1,
                failures: acc.failures ++ failures,
                warnings: acc.warnings ++ warnings
            }

          {:raised, message} ->
            %{
              acc
              | evaluated: acc.evaluated + 1,
                failures: acc.failures ++ ["#{location} raised:\n#{message}"],
                warnings: acc.warnings ++ warnings
            }
        end
    end)
  end

  defp run_block(block, state, location) do
    Code.with_diagnostics(fn ->
      try do
        quoted = Code.string_to_quoted!(block.code, file: location, line: 1)
        {value, binding, env} = Code.eval_quoted_with_env(quoted, state.binding, state.env)
        {:ok, value, %{binding: binding, env: env}}
      rescue
        exception -> {:raised, Exception.format(:error, exception, __STACKTRACE__)}
      end
    end)
  end

  defp check_expected(block, value, location) do
    case expected_value(block.code) do
      nil ->
        []

      expected ->
        actual = inspect(value)

        if actual == expected,
          do: [],
          else: ["#{location} returned #{actual}, but its #=> line says #{expected}"]
    end
  end

  defp expected_value(code) do
    case code |> String.trim_trailing() |> String.split("\n") |> List.last() do
      "#=> " <> expected -> expected
      _other -> nil
    end
  end

  defp evaluate_api_examples(readme_state) do
    main = BoundedAuthorityReportAdapter
    v3 = BoundedAuthorityReportAdapter.V3

    main_setup =
      evaluate_blocks("#{inspect(main)} moduledoc", moduledoc_blocks(main), readme_state)

    v3_setup = evaluate_blocks("#{inspect(v3)} moduledoc", moduledoc_blocks(v3), readme_state)

    [main_setup, v3_setup] ++
      evaluate_functions(main, main_setup.state) ++ evaluate_functions(v3, v3_setup.state)
  end

  # Each function's examples start from the same state, so one function's bindings never
  # leak into another's example.
  defp evaluate_functions(module, state) do
    for {{:function, name, arity}, _anno, _sig, %{"en" => doc}, _meta} <- function_docs(module),
        blocks = code_blocks(doc),
        blocks != [] do
      evaluate_blocks("#{inspect(module)}.#{name}/#{arity}", blocks, state)
    end
  end

  defp moduledoc_blocks(module) do
    {:docs_v1, _anno, :elixir, _format, %{"en" => doc}, _meta, _docs} = Code.fetch_docs(module)
    code_blocks(doc)
  end

  defp function_docs(module) do
    {:docs_v1, _anno, :elixir, _format, _moduledoc, _meta, docs} = Code.fetch_docs(module)
    Enum.sort_by(docs, fn {_kind, anno, _sig, _doc, _meta} -> :erl_anno.line(anno) end)
  end

  defp merge(results) do
    %{
      evaluated: results |> Enum.map(& &1.evaluated) |> Enum.sum(),
      failures: Enum.flat_map(results, & &1.failures),
      warnings: Enum.flat_map(results, & &1.warnings)
    }
  end

  defp assert_clean(result) do
    assert result.failures == [], Enum.join(result.failures, "\n\n")
    assert result.warnings == [], "unexpected warnings:\n" <> Enum.join(result.warnings, "\n")
  end

  ## parsing

  defp blocks_of(path), do: path |> then(&File.read!(Path.join(@root, &1))) |> code_blocks()

  # The fenced elixir blocks of a Markdown text, each with its 1-based start line and
  # whether the fragment marker is the last non-blank line above its opening fence.
  defp code_blocks(markdown) do
    markdown
    |> String.split("\n")
    |> Enum.with_index(1)
    |> collect_blocks(nil, [])
  end

  defp collect_blocks([], _previous, blocks), do: Enum.reverse(blocks)

  defp collect_blocks([{text, line} | rest], previous, blocks) do
    trimmed = String.trim(text)

    cond do
      trimmed == "```elixir" ->
        indent = String.length(text) - String.length(String.trim_leading(text))
        {code_lines, rest} = take_fence(rest, indent, [])

        block = %{
          line: line + 1,
          code: Enum.join(code_lines, "\n"),
          fragment?: previous == @fragment_marker
        }

        collect_blocks(rest, nil, [block | blocks])

      trimmed == "" ->
        collect_blocks(rest, previous, blocks)

      true ->
        collect_blocks(rest, trimmed, blocks)
    end
  end

  defp take_fence([{text, _line} | rest], indent, acc) do
    if String.trim(text) == "```" do
      {Enum.reverse(acc), rest}
    else
      take_fence(rest, indent, [String.slice(text, indent..-1//1) | acc])
    end
  end
end
