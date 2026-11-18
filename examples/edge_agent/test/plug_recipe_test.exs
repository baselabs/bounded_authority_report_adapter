defmodule EdgeAgent.PlugRecipeTest do
  @moduledoc "Executes HTTP documentation against real crypto, policy and replay storage."

  use ExUnit.Case, async: false

  @root Path.expand("../../..", __DIR__)

  setup_all do
    Code.require_file("test/support/bounded_authority_report_adapter/documentation.ex", @root)
    parser = Module.concat([BoundedAuthorityReportAdapter, Documentation])

    {_value, binding, _env} =
      Enum.reduce(
        parser.blocks(File.read!(Path.join(@root, "README.md"))),
        {nil, [], Code.env_for_eval([])},
        fn block, {_value, binding, env} ->
          if String.starts_with?(String.trim(block.code), "def deps") do
            {nil, binding, env}
          else
            quoted = Code.string_to_quoted!(block.code)
            Code.eval_quoted_with_env(quoted, binding, env)
          end
        end
      )

    # The application supplies Plug for every discovered HTTP sample.
    File.cd!(@root, fn ->
      for path <- parser.files(),
          Path.extname(path) != ".livemd",
          block <- parser.blocks(File.read!(path)),
          String.contains?(block.code, "Plug.") or
            String.contains?(block.code, "defmodule MyApp.EnvelopeVerifier") do
        Code.eval_string(block.code)
      end
    end)

    %{binding: binding}
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

    ledger = :ets.new(:admissions, [:set, :public])
    policy = MapSet.new(["archive_document"])
    revoked = MapSet.new()

    config =
      report_plug.init(%{
        issuer_key_id: "issuer-key-1",
        issuer_public_key: issuer_public_key,
        issuer: "https://issuer.example",
        audience: "https://records.example",
        target_uri: "https://records.example/archive",
        operation: "archive_document",
        clock_skew: 60,
        proof_max_age: 300,
        authorize: fn facts, _identity ->
          if MapSet.member?(policy, facts.operation), do: :ok, else: :invalid
        end,
        revocation: fn facts ->
          if MapSet.member?(revoked, facts.grant_id), do: :invalid, else: :ok
        end,
        admit: fn facts, invocation, nonce ->
          claims = [
            {{:invocation, "https://issuer.example", facts.grant_id, invocation}, true},
            {{:nonce, facts.holder_thumbprint, nonce}, true}
          ]

          if :ets.insert_new(ledger, claims), do: :ok, else: :invalid
        end
      })

    headers = [
      {"x-ba-grant", grant},
      {"x-ba-proof", proof},
      {"x-ba-invocation-id", invocation_id},
      {"x-ba-nonce", "nonce-plug-1"}
    ]

    request = fn headers, identity_public_key, config ->
      conn = %{Plug.Test.conn(:post, "/archive", raw_body) | req_headers: headers}

      conn = conn |> Plug.Conn.assign(:identity_public_key, identity_public_key)
      conn = report_plug.call(conn, config)
      {conn.status, conn.resp_body}
    end

    assert request.(headers, other_public_key, config) == {401, "invalid"}

    assert request.(List.keydelete(headers, "x-ba-proof", 0), holder_public_key, config) ==
             {401, "invalid"}

    assert request.([{"x-ba-proof", proof} | headers], holder_public_key, config) ==
             {401, "invalid"}

    empty = List.keyreplace(headers, "x-ba-proof", 0, {"x-ba-proof", ""})
    assert request.(empty, holder_public_key, config) == {401, "invalid"}

    for {method, path} <- [{:get, "/archive"}, {:post, "/other"}, {:post, "/archive?extra=1"}] do
      conn = %{Plug.Test.conn(method, path, raw_body) | req_headers: headers}
      conn = Plug.Conn.assign(conn, :identity_public_key, holder_public_key)
      response = report_plug.call(conn, config)
      assert {response.status, response.resp_body} == {401, "invalid"}
    end

    # Local policy and revocation decisions refuse before any replay claims are written.
    denied = %{config | authorize: fn _facts, _identity -> :invalid end}
    revoked = %{config | revocation: fn _facts -> :invalid end}
    assert request.(headers, holder_public_key, denied) == {401, "invalid"}
    assert request.(headers, holder_public_key, revoked) == {401, "invalid"}
    assert :ets.info(ledger, :size) == 0

    assert request.(headers, holder_public_key, config) == {200, "accepted"}
    assert request.(headers, holder_public_key, config) == {401, "invalid"}

    {:ok, %{proof: fresh_proof}} =
      BoundedAuthorityReportAdapter.sign_report(
        %{
          grant_compact: grant,
          operation: "archive_document",
          method: "POST",
          target_uri: "https://records.example/archive",
          invocation_id: invocation_id,
          cast_arguments: cast_arguments,
          nonce: "fresh-nonce"
        },
        holder
      )

    fresh_headers =
      headers
      |> List.keyreplace("x-ba-proof", 0, {"x-ba-proof", fresh_proof})
      |> List.keyreplace("x-ba-nonce", 0, {"x-ba-nonce", "fresh-nonce"})

    assert request.(fresh_headers, holder_public_key, config) == {401, "invalid"}
    assert :ets.info(ledger, :size) == 2
    :ets.delete(ledger)
  end
end
