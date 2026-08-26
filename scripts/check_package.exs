# Package boundary check — proves the SHIPPED Hex artifact works, not the source
# tree (adapted from the BAP sibling's scripts/check_package.exs, read first-hand).
#
# 1. `mix hex.build` the exact archive a consumer downloads.
# 2. Unpack it (two tar layers, via :erl_tar — Hex.Tar is not loadable in a
#    project's `mix run` context on this hex version).
# 3. Exact-set census of the payload against the expected file list — catches
#    BOTH a stale `files:` allowlist (missing) and an accidental inclusion
#    (unexpected). The docs tickets grow the allowlist; this gate keeps it honest.
# 4. Pin the outer metadata (name/version/requirements read from the LIVE
#    project config, so the gate never drifts on a bump).
# 5. Compile the unpacked package in :prod.
# 6. Compile a minimal consumer against the UNPACKED package (path dep) and run
#    a sign_report -> check_envelope smoke (positive + tampered negative) —
#    the consumer implements its own key handle, because the package ships
#    none (design C5).
#
# Everything runs under a mktemp scratch root, removed in after — re-runnable
# clean, no tree residue.

defmodule BoundedAuthorityReportAdapter.PackageCheck do
  @moduledoc false

  alias BoundedAuthorityProtocol.V1

  # The exact payload census (what contents.tar.gz must carry — the consumer's
  # actual file set). Keep in lockstep with mix.exs `files:`; the exact-set
  # check reds in BOTH directions the moment either side drifts.
  @expected_files MapSet.new([
                    ".formatter.exs",
                    "CHANGELOG.md",
                    "LICENSE",
                    "NOTICE",
                    "README.md",
                    "SECURITY.md",
                    "docs/consumer-integration.md",
                    "docs/telemetry.md",
                    "lib/bounded_authority_report_adapter.ex",
                    "lib/bounded_authority_report_adapter/telemetry.ex",
                    "mix.exs"
                  ])

  # The consumer smoke's pinned time + request fields (the conformance
  # round-trip's adapter-coherent bar, mirrored self-contained).
  @now 1_750_000_000
  @issuer_seed <<1::256>>
  @holder_seed <<2::256>>
  @issuer_key_id "issuer-2026-07"
  @issuer "https://issuer.example.test"
  @audience "https://verifier.example.test"
  @grant_id "urn:example:grant:package-check-001"
  @operation "report_external_materialization"
  @target_uri "https://api.example.test/invoke"
  @invocation_id "123e4567-e89b-42d3-a456-426614174000"

  @cast_arguments {:object, [{"record", {:object, [{"region", {:string, "us-east"}}]}}]}

  def run! do
    source_root = Path.expand("..", __DIR__)
    config = Mix.Project.config()
    version = config[:version]
    requirements = prod_requirements!(config)

    scratch_root = unique_tmp_root!()

    try do
      archive_path = Path.join(scratch_root, "bounded_authority_report_adapter-#{version}.tar")
      outer_root = Path.join(scratch_root, "outer")
      package_root = Path.join(scratch_root, "package")
      consumer_root = Path.join(scratch_root, "consumer")

      run!("mix", ["hex.build", "--output", archive_path], source_root, [])
      assert_regular_nonempty!(archive_path)

      File.mkdir_p!(outer_root)
      File.mkdir_p!(package_root)
      extract_tar!(archive_path, outer_root)
      extract_tar!(Path.join(outer_root, "contents.tar.gz"), package_root)

      check_exact_files!(package_root)
      check_metadata!(Path.join(outer_root, "metadata.config"), version, requirements)
      compile_package!(package_root)
      compile_consumer!(consumer_root, package_root)

      IO.puts("package archive boundary passed")
    after
      File.rm_rf!(scratch_root)
    end
  end

  ## fixture minting (self-contained — no test/support dependency)

  defp keypair(seed), do: :crypto.generate_key(:eddsa, :ed25519, seed)

  defp holder_thumbprint do
    {holder_pub, _} = keypair(@holder_seed)
    {:ok, raw} = V1.Jwk.public_key_thumbprint_raw(holder_pub, %{})
    raw
  end

  defp issuer_signed_grant_compact do
    {issuer_pub, issuer_priv} = keypair(@issuer_seed)

    grant = %V1.Grant{
      key_id: @issuer_key_id,
      issuer: @issuer,
      grant_id: @grant_id,
      audiences: [@audience],
      issued_at: @now - 100,
      not_before: @now - 100,
      expires_at: @now + 3600,
      holder_thumbprint: holder_thumbprint(),
      operations: [%V1.Operation{name: @operation, selectors: [:all]}]
    }

    {:ok, signing_input} = V1.grant_signing_input(grant, %{})

    signature = :crypto.sign(:eddsa, :none, signing_input.message, [issuer_priv, :ed25519])
    {:ok, compact} = V1.assemble_compact(signing_input, signature)
    {compact, issuer_pub}
  end

  ## checks

  defp check_exact_files!(package_root) do
    actual =
      package_root
      |> Path.join("**/*")
      |> Path.wildcard(match_dot: true)
      |> Enum.filter(&File.regular?/1)
      |> Enum.map(&Path.relative_to(&1, package_root))
      |> MapSet.new()

    unless actual == @expected_files do
      missing = @expected_files |> MapSet.difference(actual) |> Enum.sort()
      unexpected = actual |> MapSet.difference(@expected_files) |> Enum.sort()

      fail!(
        "package file census mismatch; missing=#{inspect(missing)} " <>
          "unexpected=#{inspect(unexpected)}"
      )
    end
  end

  defp check_metadata!(path, version, requirements) do
    metadata =
      case :file.consult(String.to_charlist(path)) do
        {:ok, terms} -> Map.new(terms)
        {:error, reason} -> fail!("cannot read Hex metadata: #{inspect(reason)}")
      end

    expected = %{
      "app" => "bounded_authority_report_adapter",
      "build_tools" => ["mix"],
      "licenses" => ["Apache-2.0"],
      "name" => "bounded_authority_report_adapter",
      # Derived from the LIVE project config's prod deps (no `only:`), in
      # declaration order — the pin covers exactly what ships, whatever the
      # runtime dep set grows to.
      "requirements" => requirements,
      "version" => version
    }

    Enum.each(expected, fn {key, expected_value} ->
      actual_value = metadata |> Map.get(key) |> decode_metadata()

      unless actual_value == expected_value do
        fail!(
          "Hex metadata #{key} must be #{inspect(expected_value)}, " <>
            "got #{inspect(actual_value)}"
        )
      end
    end)
  end

  defp decode_metadata(value) when is_binary(value), do: value
  defp decode_metadata(value) when is_list(value), do: Enum.map(value, &decode_metadata/1)
  defp decode_metadata({left, right}), do: {decode_metadata(left), decode_metadata(right)}
  defp decode_metadata(value), do: value

  defp compile_package!(package_root) do
    environment = [{"MIX_ENV", "prod"}]
    run!("mix", ["deps.get", "--only", "prod"], package_root, environment)
    run!("mix", ["compile", "--warnings-as-errors"], package_root, environment)
  end

  defp compile_consumer!(consumer_root, package_root) do
    {grant_compact, issuer_pub} = issuer_signed_grant_compact()

    File.mkdir_p!(Path.join(consumer_root, "lib"))

    File.write!(
      Path.join(consumer_root, "mix.exs"),
      """
      defmodule BoundedAuthorityReportAdapterConsumer.MixProject do
        use Mix.Project

        def project do
          [
            app: :bounded_authority_report_adapter_consumer,
            version: "0.0.0",
            elixir: "~> 1.18",
            deps: [
              {:bounded_authority_report_adapter, path: #{inspect(package_root)}}
            ]
          ]
        end
      end
      """
    )

    File.write!(
      Path.join(consumer_root, "lib/consumer.ex"),
      consumer_source(grant_compact, issuer_pub)
    )

    environment = [{"MIX_ENV", "prod"}]
    run!("mix", ["deps.get"], consumer_root, environment)
    run!("mix", ["compile", "--warnings-as-errors"], consumer_root, environment)

    run!(
      "mix",
      [
        "run",
        "--no-start",
        "-e",
        "unless BoundedAuthorityReportAdapterConsumer.smoke?(), " <>
          "do: System.halt(1)"
      ],
      consumer_root,
      environment
    )
  end

  # The consumer implements its OWN key handle (the package ships none — design
  # C5): a seeded Ed25519 pair behind the full behaviour contract. The smoke is
  # the conformance round-trip's adapter-coherent bar mirrored against the
  # UNPACKED artifact: sign_report through the handle, verify the envelope via
  # the protocol's own verifier, and a tampered-request negative so a green can
  # never be vacuous.
  defp consumer_source(grant_compact, issuer_pub) do
    """
    defmodule BoundedAuthorityReportAdapterConsumer.Handle do
      @moduledoc false
      @behaviour BoundedAuthorityReportAdapter

      # Interpolated from the script's single @holder_seed — the minted grant
      # binds THIS holder's thumbprint, so the constant has exactly one source.
      @holder_seed #{inspect(@holder_seed)}

      defp keypair, do: :crypto.generate_key(:eddsa, :ed25519, @holder_seed)

      @impl true
      def sign(message, _handle) when is_binary(message) do
        {_pub, priv} = keypair()
        {:ok, :crypto.sign(:eddsa, :none, message, [priv, :ed25519])}
      end

      def sign(_message, _handle), do: {:error, :invalid_handle}

      @impl true
      def public_key(_handle), do: {:ok, elem(keypair(), 0)}

      @impl true
      def thumbprint(_handle) do
        {:ok, raw} =
          BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw(elem(keypair(), 0), %{})

        {:ok, raw}
      end

      @impl true
      def key_identity(_handle),
        do: {:ok, {"consumer-handle-key-001", elem(keypair(), 0)}}

      @impl true
      def signing_identity(_handle),
        do: {:ok, {:holder, "consumer-handle-key-001", elem(keypair(), 0)}}
    end

    defmodule BoundedAuthorityReportAdapterConsumer do
      @moduledoc false

      alias BoundedAuthorityProtocol.V1
      alias BoundedAuthorityProtocol.V1.{Credentials, ExpectedRequest, TrustedIssuer}

      @grant_compact #{inspect(grant_compact)}
      @issuer_public_key #{inspect(issuer_pub)}
      @now #{@now}
      @cast_arguments #{inspect(@cast_arguments)}
      @invocation_id "#{@invocation_id}"
      @target_uri "#{@target_uri}"
      @operation "#{@operation}"

      defp report do
        %{
          grant_compact: @grant_compact,
          operation: @operation,
          method: "POST",
          target_uri: @target_uri,
          invocation_id: @invocation_id,
          cast_arguments: @cast_arguments,
          nonce: nil
        }
      end

      defp expected_request do
        %ExpectedRequest{
          trusted_issuer: %TrustedIssuer{key_id: "issuer-2026-07", public_key: @issuer_public_key},
          issuer: "https://issuer.example.test",
          audience: "https://verifier.example.test",
          method: "POST",
          target_uri: @target_uri,
          invocation_id: @invocation_id,
          operation: @operation,
          cast_arguments: @cast_arguments,
          evaluation_time: @now,
          clock_skew: 60,
          proof_max_age: 300,
          nonce: :not_required,
          bounds: V1.Bounds.maximum()
        }
      end

      def smoke? do
        with {:ok, %{grant: grant, proof: proof}} <-
               BoundedAuthorityReportAdapter.sign_report(
                 report(),
                 {BoundedAuthorityReportAdapterConsumer.Handle, :demo},
                 %{issued_at: @now - 50, proof_id: "package-check-001"}
               ),
             true <- grant == @grant_compact,
             {:ok, _facts} <- V1.check_envelope(%Credentials{grant: grant, proof: proof}, expected_request()),
             {:error, :invalid} <-
               V1.check_envelope(%Credentials{grant: grant, proof: proof}, %{
                 expected_request()
                 | cast_arguments: {:object, [{"record", {:object, [{"region", {:string, "tampered"}}]}}]}
               }) do
          true
        else
          failure -> IO.inspect(failure, label: "consumer smoke failure") && false
        end
      end
    end
    """
  end

  ## plumbing

  defp prod_requirements!(config) do
    config
    |> Keyword.fetch!(:deps)
    |> Enum.filter(fn
      {_name, _requirement, opts} when is_list(opts) ->
        not Keyword.has_key?(opts, :only)

      {_name, _requirement} ->
        true

      _ ->
        false
    end)
    |> Enum.map(fn
      {name, requirement} when is_binary(requirement) ->
        requirement_entry(name, requirement)

      {name, requirement, _opts} when is_binary(requirement) ->
        requirement_entry(name, requirement)

      _ ->
        fail!(
          "mix.exs must declare runtime deps in a form the package check recognizes " <>
            "(2-tuple or 3-tuple with a binary requirement)"
        )
    end)
  end

  defp requirement_entry(name, requirement) do
    [
      {"name", to_string(name)},
      {"app", to_string(name)},
      {"optional", false},
      {"requirement", requirement},
      {"repository", "hexpm"}
    ]
  end

  defp extract_tar!(archive, target) do
    case :erl_tar.extract(String.to_charlist(archive), [
           :compressed,
           {:cwd, String.to_charlist(target)}
         ]) do
      :ok -> :ok
      {:error, reason} -> fail!("cannot extract #{archive}: #{inspect(reason)}")
    end
  end

  defp unique_tmp_root! do
    template = Path.join(System.tmp_dir!(), "bounded-authority-report-package.XXXXXX")

    case System.cmd("mktemp", ["-d", template], stderr_to_stdout: true) do
      {path, 0} ->
        path = String.trim(path)

        if File.dir?(path),
          do: path,
          else: fail!("mktemp returned a missing directory")

      {output, status} ->
        fail!("mktemp exited with status #{status}: #{String.trim(output)}")
    end
  end

  defp assert_regular_nonempty!(path) do
    unless File.regular?(path) and File.stat!(path).size > 0 do
      fail!("package archive is missing or empty")
    end
  end

  defp run!(command, arguments, directory, environment) do
    options = [
      cd: directory,
      env: environment,
      into: IO.stream(:stdio, :line),
      stderr_to_stdout: true
    ]

    case System.cmd(command, arguments, options) do
      {_output, 0} -> :ok
      {_output, status} -> fail!("#{command} exited with status #{status}")
    end
  end

  defp fail!(message), do: raise("package check failed: #{message}")
end

BoundedAuthorityReportAdapter.PackageCheck.run!()
