defmodule MyApp.NonceLedger do
  @moduledoc false
  # The replay ledger the Plug recipe leaves to the reader (consumer integration §9): a real
  # ETS table keyed by (identity, nonce).
  @table __MODULE__

  def start, do: :ets.new(@table, [:named_table, :public, :set])

  def spend(identity, nonce) do
    if :ets.insert_new(@table, {{identity, nonce}}), do: :ok, else: {:error, :replayed}
  end
end

defmodule EdgeAgent.PlugRecipeTest do
  @moduledoc """
  Runs the library's Plug recipe (`docs/recipes.md`) as written, in this app because it has
  Plug. The recipe plugs into the verifier module from `docs/consumer-integration.md` §4,
  and the README's quick start signs the request, so those blocks are evaluated from the
  library's docs too. The recipe module is then called with real `Plug.Conn` requests
  carrying a real envelope: the matching request is accepted, and a replay, another
  identity's key and a missing header are rejected.
  """

  use ExUnit.Case, async: false

  @root Path.expand("../../..", __DIR__)

  setup_all do
    {_readme_handle, readme_binding} =
      eval_blocks(["README.md"], &(&1 =~ "defmodule MyApp.DevKey" or &1 =~ "V1.check_envelope("))

    eval_blocks(["docs/consumer-integration.md"], &(&1 =~ "defmodule MyApp.EnvelopeVerifier"))
    eval_blocks(["docs/recipes.md"], &(&1 =~ "defmodule MyApp.ReportPlug"))

    %{binding: readme_binding}
  end

  setup do
    MyApp.NonceLedger.start()
    :ok
  end

  test "the recipe accepts a real envelope once and rejects a replay, another key and a missing header",
       %{binding: binding} do
    dev_key = Module.concat(["MyApp", "DevKey"])
    report_plug = Module.concat(["MyApp", "ReportPlug"])
    grant = Keyword.fetch!(binding, :grant)
    holder = Keyword.fetch!(binding, :holder)
    raw_body = Keyword.fetch!(binding, :raw_body)
    cast_arguments = Keyword.fetch!(binding, :cast_arguments)
    invocation_id = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"

    {:ok, %{proof: proof}} =
      BoundedAuthorityReportAdapter.sign_report(
        %{
          grant_compact: grant,
          operation: "archive_document",
          method: "POST",
          target_uri: "https://records.example/archive",
          invocation_id: invocation_id,
          cast_arguments: cast_arguments,
          nonce: "nonce-plug-1"
        },
        holder
      )

    {:ok, issuer_public_key} = dev_key.public_key({:issuer, "issuer-key-1"})
    {:ok, holder_public_key} = dev_key.public_key({:holder, "holder-key-1"})
    {:ok, other_public_key} = dev_key.public_key({:holder, "another-key-1"})

    config =
      report_plug.init(%{
        issuer_key_id: "issuer-key-1",
        issuer_public_key: issuer_public_key,
        issuer: "https://issuer.example",
        audience: "https://records.example",
        target_uri: "https://records.example/archive",
        operation: "archive_document",
        clock_skew: 60,
        proof_max_age: 300
      })

    headers = [
      {"x-ba-grant", grant},
      {"x-ba-proof", proof},
      {"x-ba-invocation-id", invocation_id},
      {"x-ba-nonce", "nonce-plug-1"}
    ]

    request = fn headers, identity_public_key ->
      conn =
        Enum.reduce(headers, Plug.Test.conn(:post, "/archive", raw_body), fn {name, value},
                                                                             conn ->
          Plug.Conn.put_req_header(conn, name, value)
        end)

      conn = conn |> Plug.Conn.assign(:identity_public_key, identity_public_key)
      conn = report_plug.call(conn, config)
      {conn.status, conn.resp_body}
    end

    assert request.(headers, other_public_key) == {401, "invalid"}

    assert request.(List.keydelete(headers, "x-ba-proof", 0), holder_public_key) ==
             {401, "invalid"}

    assert request.(headers, holder_public_key) == {200, "accepted"}
    assert request.(headers, holder_public_key) == {401, "invalid"}
  end

  # Evaluates the elixir blocks of the given docs that match `select`, in order, in one
  # binding, and returns the last value and the binding.
  defp eval_blocks(paths, select) do
    blocks =
      for path <- paths,
          block <- elixir_blocks(File.read!(Path.join(@root, path))),
          select.(block),
          do: block

    assert blocks != [], "no matching block in #{inspect(paths)}"

    Enum.reduce(blocks, {nil, []}, fn code, {_value, binding} ->
      {value, binding} = Code.eval_string(code, binding)
      {value, binding}
    end)
  end

  defp elixir_blocks(markdown) do
    ~r/^```elixir\n(.*?)^```$/ms
    |> Regex.scan(markdown)
    |> Enum.map(fn [_, code] -> code end)
  end
end
