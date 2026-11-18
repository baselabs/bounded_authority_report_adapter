defmodule BoundedAuthorityReportAdapter.DocSamplesTest do
  @moduledoc "Executes recursively discovered CommonMark samples and public API examples."

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias BoundedAuthorityProtocol.V1.Json
  alias BoundedAuthorityReportAdapter.DocsChunk
  alias BoundedAuthorityReportAdapter.Documentation

  @root Path.expand("../", __DIR__)

  @guides Documentation.files() |> Enum.reject(&(Path.extname(&1) == ".livemd"))
  @allowed_warning ~r/redefining module (MyApp|Demo)\./

  setup_all do
    readme = evaluate_blocks("README.md", blocks_of("README.md"), new_state())
    assert_clean(readme)
    readme_state = readme.state

    guide_results =
      for path <- @guides do
        state =
          case Regex.run(~r/<!-- doc-session: ([^ ]+) -->/, File.read!(path)) do
            [_, prerequisite] ->
              prerequisite = Path.join(Path.dirname(path), prerequisite)
              result = evaluate_blocks(prerequisite, blocks_of(prerequisite), readme_state)
              assert_clean(result)
              result.state

            nil ->
              readme_state
          end

        {path, evaluate_blocks(path, blocks_of(path), state)}
      end

    # The telemetry guide attaches a logging handler; detach it before anything else signs.
    :telemetry.detach("my-app-sign-telemetry")

    api_results = merge(evaluate_api_examples(readme_state))

    %{guides: Map.new(guide_results), api: api_results, readme_state: readme_state}
  end

  test "every runnable guide block evaluates and matches its #=> value", %{guides: guides} do
    for path <- @guides do
      result = Map.fetch!(guides, path)
      assert_clean(result)
    end
  end

  test "every API doc example evaluates and matches its #=> value", %{api: api} do
    # sign_* functions of both surfaces, plus the V3 moduledoc's handle.
    assert api.evaluated >= 11, "only #{api.evaluated} API examples ran; the scan is broken"
    assert_clean(api)
  end

  test "every public function has an executed example or a doctest" do
    {:ok, modules} = :application.get_key(:bounded_authority_report_adapter, :modules)
    filter = Mix.Project.config()[:docs][:filter_modules]

    for module <- modules,
        Code.ensure_loaded!(module),
        filter.(module, %{}),
        {{:function, name, arity}, _, _, %{"en" => doc}, _} <- function_docs(module) do
      assert code_blocks(doc) != [] or String.contains?(doc, "iex>"),
             "#{inspect(module)}.#{name}/#{arity} needs an executed example"
    end
  end

  test "CommonMark discovery handles nesting, tilde and long fences without false examples" do
    markdown = """
    > ~~~~elixir
    > :nested
    > ~~~~

    ````text
    ```elixir
    :not_code
    ```
    ````

    ~~~elixir
    :top_level
    ~~~
    """

    assert Enum.map(code_blocks(markdown), &String.trim(&1.code)) == [":nested", ":top_level"]
  end

  test "the README and getting-started define the same development key handle" do
    [readme_handle, guide_handle] =
      for path <- ["README.md", "docs/guides/getting-started.md"] do
        path |> blocks_of() |> Enum.find(&(&1.code =~ "defmodule MyApp.DevKey")) |> Map.get(:code)
      end

    assert readme_handle == guide_handle
  end

  test "the custody guide and notebooks execute the same plain handle setup" do
    guide =
      "docs/guides/key-custody.md"
      |> blocks_of()
      |> Enum.find(&String.contains?(&1.code, "defmodule Demo.Custody"))

    for path <- Path.wildcard(Path.join(@root, "docs/notebooks/*.livemd")) do
      setup =
        path
        |> File.read!()
        |> code_blocks()
        |> Enum.find(&String.contains?(&1.code, "defmodule Demo.Custody"))

      assert String.starts_with?(setup.code, "defmodule Demo.Custody do"), path
      assert setup.code == guide.code, path
    end
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

    assert verifier.verify(
             raw_body,
             headers,
             holder_public_key,
             Map.put(config, :contract_major, 9)
           ) ==
             :invalid

    other_body = ~s({"document":"minutes-2026-10-02.pdf"})
    assert verifier.verify(other_body, headers, holder_public_key, config) == :invalid

    assert verifier.verify(raw_body, Map.delete(headers, "x-ba-nonce"), holder_public_key, config) ==
             :invalid
  end

  test "the consumer-integration verifier binds a P-256 identity on contract-major 3" do
    # The V3 moduledoc defines the development P-256 handle; it is looked up by name.
    ec_key = doc_module("DevP256Key")
    verifier = doc_module("EnvelopeVerifier")
    now = System.system_time(:second)
    issuer = {ec_key, {:issuer, "ec-issuer-key-1"}}
    holder = {ec_key, {:holder, "ec-holder-key-1"}}
    {:ok, issuer_public_key} = ec_key.public_key({:issuer, "ec-issuer-key-1"})
    {:ok, holder_public_key} = ec_key.public_key({:holder, "ec-holder-key-1"})
    {:ok, stranger_public_key} = ec_key.public_key({:holder, "ec-stranger-key-1"})
    {:ok, holder_thumbprint} = ec_key.thumbprint({:holder, "ec-holder-key-1"})
    {:ok, ed25519_identity} = doc_module("DevKey").public_key({:holder, "holder-key-1"})

    {:ok, %{grant: grant}} =
      BoundedAuthorityReportAdapter.V3.sign_grant(
        %{
          issuer: "https://issuer.example",
          grant_id: "urn:example:grant:p256-consumer",
          audiences: ["https://records.example"],
          issued_at: now,
          not_before: now,
          expires_at: now + 3600,
          holder_thumbprint: holder_thumbprint,
          operations: [
            %BoundedAuthorityProtocol.V3.Operation{name: "archive_document", selectors: [:all]}
          ]
        },
        issuer
      )

    raw_body = ~s({"document":"minutes-2026-10-01.pdf"})
    {:ok, cast_arguments} = Json.decode(raw_body)
    invocation_id = "5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b"

    {:ok, %{proof: proof}} =
      BoundedAuthorityReportAdapter.V3.sign_report(
        %{
          grant_compact: grant,
          operation: "archive_document",
          method: "POST",
          target_uri: "https://records.example/archive",
          invocation_id: invocation_id,
          cast_arguments: cast_arguments,
          nonce: "nonce-p256-consumer-1"
        },
        holder,
        %{issued_at: now}
      )

    headers = %{
      "x-ba-grant" => grant,
      "x-ba-proof" => proof,
      "x-ba-invocation-id" => invocation_id,
      "x-ba-nonce" => "nonce-p256-consumer-1"
    }

    config = %{
      contract_major: 3,
      issuer_key_id: "ec-issuer-key-1",
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
    assert verifier.verify(raw_body, headers, ed25519_identity, config) == :invalid
    assert verifier.verify(raw_body, headers, <<4, 1, 2>>, config) == :invalid

    # The same credentials under the contract-major-1 configuration are refused.
    assert verifier.verify(
             raw_body,
             headers,
             holder_public_key,
             Map.delete(config, :contract_major)
           ) ==
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

  # Evaluates all discovered blocks of one source in order, threading binding and env.
  defp evaluate_blocks(source, blocks, state) do
    initial = %{state: state, evaluated: 0, failures: [], warnings: []}

    Enum.reduce(blocks, initial, fn block, acc ->
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

        quoted =
          if String.starts_with?(String.trim(block.code), "def deps") do
            quote do
              defmodule MyApp.DocumentedDependencies do
                unquote(quoted)
              end

              MyApp.DocumentedDependencies.deps()
            end
          else
            quoted
          end

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

    {:ok, modules} = :application.get_key(:bounded_authority_report_adapter, :modules)
    filter = Mix.Project.config()[:docs][:filter_modules]

    helpers =
      for module <- modules,
          module not in [main, v3],
          Code.ensure_loaded!(module),
          filter.(module, %{}),
          result <- evaluate_functions(module, readme_state),
          do: result

    List.flatten([
      main_setup,
      v3_setup,
      helpers,
      evaluate_functions(main, main_setup.state),
      evaluate_functions(v3, v3_setup.state)
    ])
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
    %{language: :elixir, module_doc: %{"en" => doc}} = DocsChunk.fetch!(module)
    code_blocks(doc)
  end

  defp function_docs(module) do
    %{language: :elixir, entries: docs} = DocsChunk.fetch!(module)
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

  ## Parsing is shared with the example application's execution harness.

  defp blocks_of(path) do
    path
    |> then(&File.read!(Path.join(@root, &1)))
    |> code_blocks()
    |> Enum.reject(&String.contains?(&1.code, "Plug."))
  end

  defp code_blocks(markdown), do: Documentation.blocks(markdown)
end
